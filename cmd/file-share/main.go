// Command file-share serves the file host, its MCP endpoint and HTTP API.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/zachlatta/file-share/internal/app"
	"github.com/zachlatta/file-share/internal/config"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	switch command {
	case "serve":
	case "version":
		fmt.Fprintln(stdout, os.Getenv("SOURCE_COMMIT"))
		return 0
	default:
		fmt.Fprintln(stderr, "usage: file-share [serve|version]")
		return 2
	}
	_ = godotenv.Load() // existing environment variables win
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 1
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	a, err := app.New(startup, cfg, app.Options{Logger: logger})
	cancel()
	if err != nil {
		fmt.Fprintf(stderr, "app: %v\n", err)
		return 1
	}
	defer a.Close()
	go a.RunPurge(ctx)

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           logRequests(logger, a.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// No read/write timeouts: uploads and downloads can be gigabytes.
	}
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServe() }()
	logger.Info("file-share listening", "addr", cfg.Addr, "public_url", cfg.PublicURL, "bucket", cfg.S3Bucket,
		"retention_days", int(cfg.Retention.Hours()/24), "max_upload_mb", cfg.MaxUploadBytes>>20, "version", cfg.Version)
	select {
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "error", err)
			return 1
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}
	return 0
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// logRequests logs method, path and status. Never query strings (passwords,
// OAuth codes) and never /upload or /download tokens.
func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" {
			return
		}
		p := r.URL.Path
		for _, prefix := range []string{"/upload/", "/download/"} {
			if len(p) > len(prefix) && p[:len(prefix)] == prefix {
				p = prefix + "…"
			}
		}
		logger.Info("request", "method", r.Method, "path", p, "status", rec.status, "duration_ms", time.Since(started).Milliseconds())
	})
}
