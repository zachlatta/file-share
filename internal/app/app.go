// Package app wires configuration, storage, OAuth, the MCP endpoint and the
// public web handler into one server, and runs the retention purge loop.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zachlatta/file-share/internal/auth"
	"github.com/zachlatta/file-share/internal/blob"
	"github.com/zachlatta/file-share/internal/config"
	"github.com/zachlatta/file-share/internal/fetch"
	"github.com/zachlatta/file-share/internal/files"
	"github.com/zachlatta/file-share/internal/hcauth"
	"github.com/zachlatta/file-share/internal/mcpserver"
	"github.com/zachlatta/file-share/internal/web"
)

// Options overrides dependencies in tests.
type Options struct {
	Blobs  blob.Store
	Logger *slog.Logger
}

type App struct {
	files   *files.Service
	handler http.Handler
	logger  *slog.Logger
	cfg     config.Config
}

func New(ctx context.Context, cfg config.Config, opts Options) (*App, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	blobs := opts.Blobs
	if blobs == nil {
		s3, err := blob.NewS3(blob.S3Config{Endpoint: cfg.S3Endpoint, AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, Bucket: cfg.S3Bucket, Region: cfg.S3Region})
		if err != nil {
			return nil, err
		}
		blobs = s3
	}
	var hca *hcauth.Client
	if cfg.HCAClientID != "" {
		hca = hcauth.New(hcauth.Config{ClientID: cfg.HCAClientID, ClientSecret: cfg.HCAClientSecret, BaseURL: cfg.HCAURL, RedirectURL: cfg.PublicURL + "/oauth/callback"})
	}
	svc, err := files.Open(ctx, files.Config{
		DatabaseURL: cfg.DatabaseURL, Blobs: blobs, BaseURL: cfg.PublicURL,
		Retention: cfg.Retention, MaxBytes: cfg.MaxUploadBytes, EmailLogin: hca != nil,
	})
	if err != nil {
		return nil, err
	}
	authService := auth.NewService(auth.Config{Secret: cfg.Secret, BaseURL: cfg.PublicURL, Logger: logger})

	mux := http.NewServeMux()
	authService.RegisterHandlers(mux)
	web.New(web.Config{Files: svc, Auth: authService, HCA: hca, Version: cfg.Version,
		AdminToken: cfg.AdminToken, ClientIPHeader: cfg.ClientIPHeader, Logger: logger}).Register(mux)

	mcpServer := mcpserver.New(mcpserver.Config{Files: svc, Auth: authService, Fetcher: fetch.New(fetch.Options{}), Version: cfg.Version})
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	crossOrigin := http.NewCrossOriginProtection()
	if err := crossOrigin.AddTrustedOrigin(cfg.PublicURL); err != nil {
		svc.Close()
		return nil, fmt.Errorf("configure MCP origin protection: %w", err)
	}
	protected := crossOrigin.Handler(authService.RequireBearer(mcpHandler))
	// Explicit methods keep /mcp from overlapping the GET /{ns} pattern.
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		mux.Handle(method+" /mcp", protected)
	}
	return &App{files: svc, handler: mux, logger: logger, cfg: cfg}, nil
}

func (a *App) Handler() http.Handler { return a.handler }

func (a *App) Close() { a.files.Close() }

// RunPurge enforces retention until ctx is cancelled: once at start, then
// every PurgeInterval.
func (a *App) RunPurge(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.PurgeInterval)
	defer ticker.Stop()
	for {
		res, err := a.files.Purge(ctx)
		if err != nil {
			a.logger.Error("purge failed", "error", err)
		} else if res.Files+res.Versions > 0 {
			a.logger.Info("purged expired files", "files", res.Files, "versions", res.Versions, "blobs", res.Blobs)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
