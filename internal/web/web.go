// Package web serves files publicly at /{namespace}/{name}, gates
// password-protected files, and exposes a small HTTP API for scripts plus
// signed upload and download URLs for agents.
package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zachlatta/file-share/internal/auth"
	"github.com/zachlatta/file-share/internal/files"
)

type Config struct {
	Files   *files.Service
	Auth    *auth.Service
	Version string
}

type Handler struct {
	files   *files.Service
	auth    *auth.Service
	version string
	secure  bool
}

func New(cfg Config) *Handler {
	return &Handler{files: cfg.Files, auth: cfg.Auth, version: cfg.Version, secure: strings.HasPrefix(cfg.Files.BaseURL(), "https://")}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /{$}", h.home)
	mux.HandleFunc("GET /{ns}", h.namespaceRedirect)

	api := func(f http.HandlerFunc) http.Handler { return h.auth.RequireStaticBearer(f) }
	mux.Handle("GET /api/files", api(h.apiList))
	mux.Handle("POST /api/files", api(h.apiUpload))
	mux.Handle("GET /api/files/{id}", api(h.apiGet))
	mux.Handle("PUT /api/files/{id}/content", api(h.apiReplace))
	mux.Handle("DELETE /api/files/{id}", api(h.apiDelete))
	mux.Handle("POST /api/files/{id}/restore", api(h.apiRestore))

	mux.HandleFunc("PUT /upload/{token}", h.signedUpload)
	mux.HandleFunc("POST /upload/{token}", h.signedUpload)
	mux.HandleFunc("GET /download/{token}", h.signedDownload)

	mux.HandleFunc("GET /{ns}/{name...}", h.serve)
	mux.HandleFunc("POST /{ns}/{name...}", h.unlock)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	storage := "ok"
	if err := h.files.Ping(ctx); err != nil {
		storage = err.Error()
	}
	// Always 200: the process is alive even if the NAS is briefly away, and
	// restarting the container would not help.
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": h.version, "storage": storage})
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
	if f.HasPassword && !h.unlocked(r, f) {
		renderPassword(w, http.StatusUnauthorized, f, "")
		return
	}
	h.send(w, r, f, 0)
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
	if !h.files.CheckPassword(f, r.PostFormValue("password")) {
		time.Sleep(250 * time.Millisecond) // blunt online guessing
		renderPassword(w, http.StatusUnauthorized, f, "Wrong password.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(f.ID), Value: h.auth.MAC("file-password", f.ID, f.PasswordStamp),
		Path: "/" + f.Namespace + "/", MaxAge: 30 * 24 * 3600,
		HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
}

func cookieName(fileID string) string { return "fsp_" + strings.ReplaceAll(fileID, "-", "") }

func (h *Handler) unlocked(r *http.Request, f files.File) bool {
	if c, err := r.Cookie(cookieName(f.ID)); err == nil && c.Value == h.auth.MAC("file-password", f.ID, f.PasswordStamp) {
		return true
	}
	if pw := r.URL.Query().Get("password"); pw != "" && h.files.CheckPassword(f, pw) {
		return true
	}
	if _, pw, ok := r.BasicAuth(); ok && h.files.CheckPassword(f, pw) {
		return true
	}
	return false
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
	if f.HasPassword || version != 0 {
		header.Set("Cache-Control", "private, no-cache")
	} else {
		header.Set("Cache-Control", "public, max-age=60, must-revalidate")
	}
	// Active content runs in an opaque origin so it can never act as this
	// site (whose OAuth endpoints and password cookies share the origin).
	mediaType, _, _ := mime.ParseMediaType(v.ContentType)
	if mediaType == "text/html" || mediaType == "image/svg+xml" || mediaType == "application/xhtml+xml" || mediaType == "application/xml" || mediaType == "text/xml" {
		header.Set("Content-Security-Policy", "sandbox allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads")
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
	w.Header().Set("Cache-Control", "private, no-store")
	h.send(w, r, f, grant.Version)
}

// upload is an incoming file from either a multipart form (field "file",
// plus optional fields name, namespace, password) or a raw body (with query
// parameters name, namespace, password and the Content-Type header).
type upload struct {
	name, namespace, password, contentType string
	body                                   io.Reader
	size                                   int64
}

// readUpload calls fn with the upload. A raw body is streamed straight
// through. A multipart file part is spooled to a temporary file (capped at the
// upload limit) so that fields sent after it, as curl -F does, still apply.
func (h *Handler) readUpload(r *http.Request, fn func(upload) (files.File, error)) (files.File, error) {
	q := r.URL.Query()
	u := upload{name: q.Get("name"), namespace: q.Get("namespace"), password: q.Get("password")}
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
			Body: u.body, Size: u.size, Password: u.password, Client: client,
		})
	})
}

func (h *Handler) replace(r *http.Request, client, id string) (files.File, error) {
	return h.readUpload(r, func(u upload) (files.File, error) {
		return h.files.Replace(r.Context(), id, files.ReplaceInput{ContentType: u.contentType, Body: u.body, Size: u.size, Client: client})
	})
}

func (h *Handler) apiUpload(w http.ResponseWriter, r *http.Request) {
	f, err := h.create(r, auth.ClientName(r.Context()), "", "")
	respond(w, http.StatusCreated, f, err)
}

func (h *Handler) apiReplace(w http.ResponseWriter, r *http.Request) {
	f, err := h.replace(r, auth.ClientName(r.Context()), r.PathValue("id"))
	respond(w, http.StatusOK, f, err)
}

func (h *Handler) apiGet(w http.ResponseWriter, r *http.Request) {
	f, err := h.files.Get(r.Context(), r.PathValue("id"))
	respond(w, http.StatusOK, f, err)
}

func (h *Handler) apiDelete(w http.ResponseWriter, r *http.Request) {
	f, err := h.files.Delete(r.Context(), r.PathValue("id"))
	respond(w, http.StatusOK, f, err)
}

func (h *Handler) apiRestore(w http.ResponseWriter, r *http.Request) {
	f, err := h.files.Restore(r.Context(), r.PathValue("id"))
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

func (h *Handler) signedUpload(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	grant, err := h.auth.VerifyUpload(token)
	if err != nil {
		http.Error(w, "invalid or expired upload link", http.StatusUnauthorized)
		return
	}
	client := grant.ClientName
	if client == "" {
		client = "upload-url"
	}
	q := r.URL.Query()
	// Chunked mode, for bodies larger than a proxy allows in one request:
	// PUT ?part=1..N, then POST ?complete=N.
	sum := sha256.Sum256([]byte(token))
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
		status := http.StatusCreated
		f, err := h.files.CompleteParts(r.Context(), uploadKey, parts, func(body io.Reader) (files.File, error) {
			if grant.FileID != "" {
				status = http.StatusOK
				return h.files.Replace(r.Context(), grant.FileID, files.ReplaceInput{Body: body, Size: -1, Client: client})
			}
			return h.files.Upload(r.Context(), files.UploadInput{Namespace: grant.Namespace, Name: grant.Filename, Body: body, Size: -1, Client: client})
		})
		respond(w, status, f, err)
		return
	}
	if grant.FileID != "" {
		f, err := h.replace(r, client, grant.FileID)
		respond(w, http.StatusOK, f, err)
		return
	}
	f, err := h.create(r, client, grant.Namespace, grant.Filename)
	respond(w, http.StatusCreated, f, err)
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
	case errors.Is(err, files.ErrExists):
		return http.StatusConflict
	case errors.Is(err, files.ErrTooLarge), errors.As(err, &maxBytes):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, files.ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func renderPassword(w http.ResponseWriter, status int, f files.File, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_ = passwordPage.Execute(w, map[string]string{"Name": path.Base(f.Name), "Error": message})
}

var passwordPage = template.Must(template.New("password").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Password required</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:28rem;margin:15vh auto;padding:0 1rem;color:#172026}input{display:block;width:100%;box-sizing:border-box;margin:.5rem 0 1rem;padding:.7rem;font:inherit;border:1px solid #b8c1cc;border-radius:6px}button{padding:.7rem 1rem;font:inherit;border:0;border-radius:6px;background:#172026;color:#fff;cursor:pointer}.error{color:#a00}</style></head>
<body><h1>🔒 {{.Name}}</h1><p>This file is password protected.</p>
{{with .Error}}<p class="error">{{.}}</p>{{end}}
<form method="post"><label for="password">Password</label><input id="password" name="password" type="password" autofocus required autocomplete="current-password"><button type="submit">Open</button></form></body></html>`))
