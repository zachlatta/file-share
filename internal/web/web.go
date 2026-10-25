// Package web serves files publicly at /{namespace}/{name}, gates
// password-protected files, and exposes a small HTTP API for scripts plus
// signed upload and download URLs for agents.
package web

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/zachlatta/file-share/internal/auth"
	"github.com/zachlatta/file-share/internal/files"
	"github.com/zachlatta/file-share/internal/hcauth"
)

type Config struct {
	Files *files.Service
	Auth  *auth.Service
	// HCA enables "Sign in with Hack Club" for email-restricted files. Nil
	// disables it.
	HCA     *hcauth.Client
	Version string
	// AdminToken unlocks the /admin audit dashboard. Empty disables it.
	AdminToken string
	// ClientIPHeader is the trusted proxy header holding the visitor IP.
	ClientIPHeader string
	Logger         *slog.Logger
}

type Handler struct {
	files      *files.Service
	auth       *auth.Service
	hca        *hcauth.Client
	version    string
	secure     bool
	adminToken string
	ipHeader   string
	logger     *slog.Logger
	passwords  *failureLimiter
}

func New(cfg Config) *Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		files: cfg.Files, auth: cfg.Auth, hca: cfg.HCA, version: cfg.Version,
		secure:     strings.HasPrefix(cfg.Files.BaseURL(), "https://"),
		adminToken: cfg.AdminToken, ipHeader: cfg.ClientIPHeader, logger: logger,
		passwords: newFailureLimiter(maxPasswordFailures, passwordWindow),
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /{$}", h.home)
	mux.HandleFunc("GET /{ns}", h.namespaceRedirect)

	api := func(f http.HandlerFunc) http.Handler { return h.auth.RequireStaticBearer(f) }
	mux.Handle("GET /api/files", api(h.apiList))
	mux.Handle("POST /api/files", api(h.apiUpload))
	mux.Handle("GET /api/files/{id}", api(h.apiGet))
	mux.Handle("PATCH /api/files/{id}", api(h.apiUpdate))
	mux.Handle("GET /api/files/{id}/content", api(h.apiDownload))
	mux.Handle("PUT /api/files/{id}/content", api(h.apiReplace))
	mux.Handle("GET /api/files/{id}/versions", api(h.apiVersions))
	mux.Handle("POST /api/files/{id}/rollback", api(h.apiRollback))
	mux.Handle("DELETE /api/files/{id}", api(h.apiDelete))
	mux.Handle("POST /api/files/{id}/restore", api(h.apiRestore))

	mux.HandleFunc("PUT /upload/{token}", h.signedUpload)
	mux.HandleFunc("POST /upload/{token}", h.signedUpload)
	mux.HandleFunc("GET /download/{token}", h.signedDownload)

	mux.HandleFunc("GET /oauth/hackclub", h.loginStart)
	mux.HandleFunc("GET /oauth/callback", h.loginCallback)

	h.registerAdmin(mux)

	mux.HandleFunc("GET /{ns}/{name...}", h.serve)
	mux.HandleFunc("POST /{ns}/{name...}", h.unlock)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	status, storage := "ok", "ok"
	if err := h.files.Ping(ctx); err != nil {
		h.logger.Warn("health check failed", "error", err)
		status, storage = "degraded", healthProblem(err)
	}
	// Always 200: the process is alive even if the NAS is briefly away, and
	// restarting the container would not help. The status still says so.
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "version": h.version, "storage": storage})
}

// healthProblem names the failed dependency and a coarse cause. /healthz is
// public, so the raw error, which holds private addresses and the bucket
// name, only goes to the server log.
func healthProblem(err error) string {
	component := "storage"
	var pe *files.PingError
	if errors.As(err, &pe) {
		component = pe.Component
	}
	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return component + ": connection refused"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return component + ": timed out"
	default:
		return component + ": unavailable"
	}
}

func (h *Handler) home(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>file-share</title>
<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:12vh auto;padding:0 1rem;color:#172026}</style></head>
<body><h1>file-share</h1><p>A personal file host. Files live at unguessable URLs; there is nothing to browse here.</p>
<p><a href="https://github.com/zachlatta/file-share">Source</a></p></body></html>`)
}

func (h *Handler) namespaceRedirect(w http.ResponseWriter, r *http.Request) {
	if _, err := uuid.Parse(r.PathValue("ns")); err != nil {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/"+r.PathValue("ns")+"/", http.StatusMovedPermanently)
}

func (h *Handler) lookup(r *http.Request) (files.File, error) {
	name := r.PathValue("name")
	if name == "" || strings.HasSuffix(name, "/") {
		name += "index.html"
	}
	return h.files.Lookup(r.Context(), r.PathValue("ns"), name)
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	f, err := h.lookup(r)
	if err != nil {
		h.notFound(w, r, err)
		return
	}
	if f.Restricted() {
		via, email, denial := h.access(r, f)
		if via == "" {
			switch denial.event {
			case "wrong_password":
				status := h.renderGate(w, r, f, "Wrong password.", 0)
				h.audit(r, f, "wrong_password", denial.via, email, status, f.Version)
			case "limited":
				h.renderGate(w, r, f, tooManyPasswords, http.StatusTooManyRequests)
			default:
				status := h.renderGate(w, r, f, "", 0)
				h.audit(r, f, "denied", "", email, status, f.Version)
			}
			return
		}
		if countsAsView(r) {
			h.audit(r, f, "view", via, email, http.StatusOK, f.Version)
		}
	}
	started := time.Now()
	cw := &countingWriter{ResponseWriter: w}
	h.send(cw, r, f, 0)
	h.logRequest(r, f, cw, time.Since(started))
}

// unlock handles the password form.
func (h *Handler) unlock(w http.ResponseWriter, r *http.Request) {
	f, err := h.lookup(r)
	if err != nil {
		h.notFound(w, r, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if !f.HasPassword {
		http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
		return
	}
	if !h.passwords.allowed(f.ID) {
		h.renderGate(w, r, f, tooManyPasswords, http.StatusTooManyRequests)
		return
	}
	if !h.checkPassword(f, r.PostFormValue("password")) {
		status := h.renderGate(w, r, f, "Wrong password.", 0)
		h.audit(r, f, "wrong_password", "password_form", h.sessionEmail(r, f.Namespace), status, f.Version)
		return
	}
	h.audit(r, f, "unlock", "password_form", h.sessionEmail(r, f.Namespace), http.StatusSeeOther, f.Version)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(f.ID), Value: h.auth.MAC("file-password", f.ID, f.PasswordStamp),
		Path: "/" + f.Namespace + "/", MaxAge: 30 * 24 * 3600,
		HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
}

func cookieName(fileID string) string { return "fsp_" + strings.ReplaceAll(fileID, "-", "") }

const tooManyPasswords = "Too many wrong passwords for this file. Try again in a few minutes."

// denial says why a request that sent a password was turned away: event is
// "wrong_password" (via how it was sent) or "limited", or "" if no password
// was sent.
type denial struct{ event, via string }

// checkPassword checks a password and counts a wrong one against the file.
func (h *Handler) checkPassword(f files.File, password string) bool {
	if h.files.CheckPassword(f, password) {
		return true
	}
	h.passwords.fail(f.ID)
	time.Sleep(wrongPasswordDelay)
	return false
}

// access reports how a request may open a restricted file ("" if it may
// not), the signed-in email, if any, and why a sent password failed.
func (h *Handler) access(r *http.Request, f files.File) (via, email string, d denial) {
	if len(f.AllowedEmails) > 0 {
		email = h.sessionEmail(r, f.Namespace)
		if f.AllowsEmail(email) {
			return "email", email, d
		}
	}
	if !f.HasPassword {
		return "", email, d
	}
	if c, err := r.Cookie(cookieName(f.ID)); err == nil && c.Value == h.auth.MAC("file-password", f.ID, f.PasswordStamp) {
		return "password_cookie", email, d
	}
	pw, via := r.URL.Query().Get("password"), "password_query"
	if pw == "" {
		if _, basic, ok := r.BasicAuth(); ok && basic != "" {
			pw, via = basic, "basic_auth"
		}
	}
	switch {
	case pw == "":
		return "", email, d
	case !h.passwords.allowed(f.ID):
		return "", email, denial{event: "limited"}
	case h.checkPassword(f, pw):
		return via, email, d
	default:
		return "", email, denial{event: "wrong_password", via: via}
	}
}

// send streams a version of f, supporting ranges and conditional requests.
func (h *Handler) send(w http.ResponseWriter, r *http.Request, f files.File, version int) {
	obj, v, err := h.files.Open(r.Context(), f.ID, version)
	if err != nil {
		h.notFound(w, r, err)
		return
	}
	defer obj.Close()
	header := w.Header()
	header.Set("Content-Type", v.ContentType)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("ETag", `"`+v.SHA256+`"`)
	header.Set("Referrer-Policy", "no-referrer")
	disposition := "inline"
	if r.URL.Query().Has("download") {
		disposition = "attachment"
	}
	header.Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": path.Base(f.Name)}))
	switch {
	case header.Get("Cache-Control") != "": // set by the caller
	case f.Restricted() || version != 0 || isMedia(v.ContentType):
		// Media skips Cloudflare's cache so every range request reaches the
		// request log, which is how listening is measured.
		header.Set("Cache-Control", "private, no-cache")
	default:
		header.Set("Cache-Control", "public, max-age=60, must-revalidate")
	}
	http.ServeContent(w, r, "", v.CreatedAt, obj)
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, files.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	http.Error(w, "storage unavailable", http.StatusBadGateway)
}

func (h *Handler) signedDownload(w http.ResponseWriter, r *http.Request) {
	grant, err := h.auth.VerifyDownload(r.PathValue("token"))
	if err != nil {
		http.Error(w, "invalid or expired download link", http.StatusUnauthorized)
		return
	}
	f, err := h.files.Get(r.Context(), grant.FileID)
	if err != nil {
		h.notFound(w, r, err)
		return
	}
	if f.Restricted() && countsAsView(r) {
		version := grant.Version
		if version <= 0 {
			version = f.Version
		}
		h.audit(r, f, "view", "download_url", "", http.StatusOK, version)
	}
	w.Header().Set("Cache-Control", "private, no-store")
	h.send(w, r, f, grant.Version)
}

// upload is an incoming file from either a multipart form (field "file",
// plus optional fields name, namespace, password, emails) or a raw body (with
// query parameters name, namespace, password, emails and the Content-Type
// header). emails is a comma-separated list of addresses or @domains.
type upload struct {
	name, namespace, password, contentType string
	emails                                 []string
	body                                   io.Reader
	size                                   int64
}

// splitEmails reads a comma- or space-separated list of emails.
func splitEmails(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
}

// readUpload calls fn with the upload. A raw body is streamed straight
// through. A multipart file part is spooled to a temporary file (capped at the
// upload limit) so that fields sent after it, as curl -F does, still apply.
func (h *Handler) readUpload(r *http.Request, fn func(upload) (files.File, error)) (files.File, error) {
	q := r.URL.Query()
	u := upload{name: q.Get("name"), namespace: q.Get("namespace"), password: q.Get("password"), emails: splitEmails(q.Get("emails"))}
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "multipart/form-data" {
		u.contentType = r.Header.Get("Content-Type")
		if mediaType == "application/x-www-form-urlencoded" {
			u.contentType = "" // curl --data default; not meaningful
		}
		u.body, u.size = r.Body, r.ContentLength
		if u.size == 0 {
			u.size = -1
		}
		return fn(u)
	}
	reader, err := r.MultipartReader()
	if err != nil {
		return files.File{}, fmt.Errorf("%w: %v", files.ErrInvalid, err)
	}
	var spool *os.File
	defer func() {
		if spool != nil {
			_ = spool.Close()
			_ = os.Remove(spool.Name())
		}
	}()
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return files.File{}, fmt.Errorf("%w: %v", files.ErrInvalid, err)
		}
		if part.FormName() == "file" {
			if spool != nil {
				return files.File{}, fmt.Errorf("%w: send one \"file\" field per request", files.ErrInvalid)
			}
			if spool, err = os.CreateTemp("", "file-share-upload-*"); err != nil {
				return files.File{}, err
			}
			limit := h.files.MaxBytes()
			src := io.Reader(part)
			if limit > 0 {
				src = io.LimitReader(part, limit+1)
			}
			n, err := io.Copy(spool, src)
			if err != nil {
				return files.File{}, fmt.Errorf("%w: reading upload: %v", files.ErrInvalid, err)
			}
			if limit > 0 && n > limit {
				return files.File{}, files.ErrTooLarge
			}
			if u.name == "" {
				u.name = part.FileName()
			}
			u.contentType, u.size = part.Header.Get("Content-Type"), n
			continue
		}
		value, _ := io.ReadAll(io.LimitReader(part, 4<<10))
		switch part.FormName() {
		case "name":
			u.name = string(value)
		case "namespace":
			u.namespace = string(value)
		case "password":
			u.password = string(value)
		case "emails":
			u.emails = splitEmails(string(value))
		}
	}
	if spool == nil {
		return files.File{}, fmt.Errorf("%w: multipart body has no \"file\" field", files.ErrInvalid)
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return files.File{}, err
	}
	u.body = spool
	return fn(u)
}

func (h *Handler) create(r *http.Request, client, namespace, name string) (files.File, error) {
	return h.readUpload(r, func(u upload) (files.File, error) {
		if name != "" {
			u.name = name
		}
		if namespace != "" {
			u.namespace = namespace
		}
		return h.files.Upload(r.Context(), files.UploadInput{
			Namespace: u.namespace, Name: u.name, ContentType: u.contentType,
			Body: u.body, Size: u.size, Password: u.password, AllowedEmails: u.emails, Client: client,
		})
	})
}

func (h *Handler) replace(r *http.Request, client, id string, expected int) (files.File, error) {
	return h.readUpload(r, func(u upload) (files.File, error) {
		return h.files.Replace(r.Context(), id, files.ReplaceInput{ContentType: u.contentType, Body: u.body, Size: u.size, Client: client, ExpectedVersion: expected})
	})
}

// apiFile resolves the {id} path value, which may be a file ID, a public URL
// or "namespace/name" (URL-escaped).
func (h *Handler) apiFile(r *http.Request) (files.File, error) {
	return h.files.Resolve(r.Context(), r.PathValue("id"))
}

// queryInt reads an optional non-negative integer query parameter.
func queryInt(r *http.Request, key string) (int, error) {
	value := r.URL.Query().Get(key)
	if value == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: %s must be a version number", files.ErrInvalid, key)
	}
	return n, nil
}

func (h *Handler) apiUpload(w http.ResponseWriter, r *http.Request) {
	f, err := h.create(r, auth.ClientName(r.Context()), "", "")
	respond(w, http.StatusCreated, f, err)
}

func (h *Handler) apiReplace(w http.ResponseWriter, r *http.Request) {
	expected, err := queryInt(r, "expected_version")
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	f, err := h.apiFile(r)
	if err == nil {
		f, err = h.replace(r, auth.ClientName(r.Context()), f.ID, expected)
	}
	respond(w, http.StatusOK, f, err)
}

func (h *Handler) apiGet(w http.ResponseWriter, r *http.Request) {
	f, err := h.apiFile(r)
	respond(w, http.StatusOK, f, err)
}

// apiDownload returns the exact bytes of a version (?version=N, default
// current), even for restricted or deleted files.
func (h *Handler) apiDownload(w http.ResponseWriter, r *http.Request) {
	version, err := queryInt(r, "version")
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	f, err := h.apiFile(r)
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	if f.Restricted() && countsAsView(r) {
		h.audit(r, f, "view", "api", "", http.StatusOK, cmp.Or(version, f.Version))
	}
	w.Header().Set("Cache-Control", "private, no-store")
	h.send(w, r, f, version)
}

func (h *Handler) apiVersions(w http.ResponseWriter, r *http.Request) {
	f, err := h.apiFile(r)
	var versions []files.Version
	if err == nil {
		versions, err = h.files.Versions(r.Context(), f.ID)
	}
	respond(w, http.StatusOK, map[string]any{"versions": versions}, err)
}

func (h *Handler) apiRollback(w http.ResponseWriter, r *http.Request) {
	version, err := queryInt(r, "version")
	if err == nil && version == 0 {
		err = fmt.Errorf("%w: ?version= is required", files.ErrInvalid)
	}
	var f files.File
	if err == nil {
		f, err = h.apiFile(r)
	}
	if err == nil {
		f, err = h.files.Rollback(r.Context(), f.ID, version, auth.ClientName(r.Context()))
	}
	respond(w, http.StatusOK, f, err)
}

// fileUpdate is the PATCH body. Omitted fields are left alone. An empty
// password removes the password; an empty allowed_emails list removes the
// email restriction.
type fileUpdate struct {
	Name          *string   `json:"name"`
	Password      *string   `json:"password"`
	AllowedEmails *[]string `json:"allowed_emails"`
}

func (h *Handler) apiUpdate(w http.ResponseWriter, r *http.Request) {
	var in fileUpdate
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		respond(w, 0, nil, fmt.Errorf("%w: body must be JSON with name, password and/or allowed_emails: %v", files.ErrInvalid, err))
		return
	}
	if in.Name == nil && in.Password == nil && in.AllowedEmails == nil {
		respond(w, 0, nil, fmt.Errorf("%w: set at least one of name, password or allowed_emails", files.ErrInvalid))
		return
	}
	f, err := h.apiFile(r)
	if err == nil && in.AllowedEmails != nil {
		f, err = h.files.SetAllowedEmails(r.Context(), f.ID, *in.AllowedEmails)
	}
	if err == nil && in.Password != nil {
		f, err = h.files.SetPassword(r.Context(), f.ID, *in.Password)
	}
	if err == nil && in.Name != nil && *in.Name != f.Name {
		f, err = h.files.Rename(r.Context(), f.ID, *in.Name)
	}
	respond(w, http.StatusOK, f, err)
}

func (h *Handler) apiDelete(w http.ResponseWriter, r *http.Request) {
	f, err := h.apiFile(r)
	if err == nil {
		f, err = h.files.Delete(r.Context(), f.ID)
	}
	respond(w, http.StatusOK, f, err)
}

func (h *Handler) apiRestore(w http.ResponseWriter, r *http.Request) {
	f, err := h.apiFile(r)
	if err == nil {
		f, err = h.files.Restore(r.Context(), f.ID)
	}
	respond(w, http.StatusOK, f, err)
}

func (h *Handler) apiList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	list, err := h.files.List(r.Context(), files.ListOptions{
		Namespace: q.Get("namespace"), Query: q.Get("q"), Deleted: q.Get("deleted") == "true", Limit: limit, Offset: offset,
	})
	if list == nil {
		list = []files.File{}
	}
	respond(w, http.StatusOK, map[string]any{"files": list}, err)
}

// signedUpload serves single-use upload links from create_upload_url. The
// link decides where the file goes and who can open it; the request sends the
// bytes and, if the link has no name, the file name (multipart file name or
// ?name=).
func (h *Handler) signedUpload(w http.ResponseWriter, r *http.Request) {
	linkID, err := h.auth.VerifyUpload(r.PathValue("token"))
	if err != nil {
		http.Error(w, "invalid or expired upload link", http.StatusUnauthorized)
		return
	}
	link, err := h.files.UploadLink(r.Context(), linkID)
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	status := http.StatusCreated
	if link.FileID != "" {
		status = http.StatusOK
	}
	q := r.URL.Query()
	// Chunked mode, for bodies larger than a proxy allows in one request:
	// PUT ?part=1..N, then POST ?complete=N.
	sum := sha256.Sum256([]byte(linkID))
	uploadKey := hex.EncodeToString(sum[:16])
	if q.Has("part") {
		n, err := strconv.Atoi(q.Get("part"))
		if err != nil {
			respond(w, 0, nil, fmt.Errorf("%w: part must be a number", files.ErrInvalid))
			return
		}
		size := r.ContentLength
		if size == 0 {
			size = -1
		}
		written, err := h.files.PutPart(r.Context(), uploadKey, n, r.Body, size)
		respond(w, http.StatusOK, map[string]any{"part": n, "size": written}, err)
		return
	}
	if q.Has("complete") {
		parts, err := strconv.Atoi(q.Get("complete"))
		if err != nil {
			respond(w, 0, nil, fmt.Errorf("%w: complete must be the number of parts", files.ErrInvalid))
			return
		}
		f, err := h.files.CompleteParts(r.Context(), uploadKey, parts, func(body io.Reader) (files.File, error) {
			return h.files.UploadWithLink(r.Context(), linkID, files.LinkUpload{Name: q.Get("name"), Body: body, Size: -1})
		})
		respond(w, status, f, err)
		return
	}
	f, err := h.readUpload(r, func(u upload) (files.File, error) {
		if u.namespace != "" || u.password != "" || len(u.emails) > 0 {
			return files.File{}, fmt.Errorf("%w: namespace, password and emails are set when the upload URL is created, not in the upload", files.ErrInvalid)
		}
		return h.files.UploadWithLink(r.Context(), linkID, files.LinkUpload{Name: u.name, ContentType: u.contentType, Body: u.body, Size: u.size})
	})
	respond(w, status, f, err)
}

func respond(w http.ResponseWriter, status int, v any, err error) {
	if err != nil {
		writeJSON(w, StatusFor(err), map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, status, v)
}

// StatusFor maps domain errors to HTTP statuses.
func StatusFor(err error) int {
	var maxBytes *http.MaxBytesError
	switch {
	case errors.Is(err, files.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, files.ErrExists), errors.Is(err, files.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, files.ErrTooLarge), errors.As(err, &maxBytes):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, files.ErrInvalid):
		return http.StatusBadRequest
	case errors.Is(err, files.ErrLinkUsed):
		return http.StatusGone
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
