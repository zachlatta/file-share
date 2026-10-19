package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zachlatta/file-share/internal/files"
)

//go:embed admin
var adminAssets embed.FS

// The dashboard never keeps the admin token in a cookie or web storage:
// uploaded HTML runs on this origin and could read either. The page holds the
// token in memory and sends it as a bearer header. COOP severs any opener, so
// an uploaded page cannot open the dashboard and script it, and frame-ancestors
// stops it from framing it.
const adminCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
	"form-action 'none'; frame-ancestors 'none'; base-uri 'none'"

func (h *Handler) registerAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", h.adminAsset("admin/index.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /admin/app.js", h.adminAsset("admin/app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /admin/app.css", h.adminAsset("admin/app.css", "text/css; charset=utf-8"))
	mux.Handle("GET /api/admin/access", h.requireAdmin(h.adminAccess))
	mux.Handle("GET /api/admin/files", h.requireAdmin(h.adminFiles))
	mux.Handle("GET /api/admin/listening", h.requireAdmin(h.adminListening))
}

func (h *Handler) adminAsset(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.adminToken == "" {
			http.NotFound(w, r)
			return
		}
		data, err := adminAssets.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		header := w.Header()
		header.Set("Content-Type", contentType)
		header.Set("Content-Security-Policy", adminCSP)
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("X-Frame-Options", "DENY")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	}
}

// requireAdmin checks "Authorization: Bearer <ADMIN_TOKEN>" in constant time.
func (h *Handler) requireAdmin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.adminToken == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		header := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(header, "Bearer ")
		got, want := sha256.Sum256([]byte(strings.TrimSpace(token))), sha256.Sum256([]byte(h.adminToken))
		if !ok || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="file-share-admin"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid admin token"})
			return
		}
		next(w, r)
	})
}

func (h *Handler) adminAccess(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	events, err := h.files.ListAccess(r.Context(), files.AccessQuery{
		FileID: q.Get("file"), Event: q.Get("event"), Search: q.Get("q"), Before: before, Limit: limit,
	})
	if events == nil {
		events = []files.AccessEvent{}
	}
	respond(w, http.StatusOK, map[string]any{"events": events}, err)
}

func (h *Handler) adminFiles(w http.ResponseWriter, r *http.Request) {
	list, err := h.files.RestrictedFiles(r.Context())
	if list == nil {
		list = []files.RestrictedFile{}
	}
	respond(w, http.StatusOK, map[string]any{"files": list}, err)
}

func (h *Handler) adminListening(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var since time.Time
	if v := q.Get("since"); v != "" {
		var err error
		if since, err = time.Parse(time.RFC3339, v); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "since must be an RFC 3339 time"})
			return
		}
	}
	buckets, _ := strconv.Atoi(q.Get("buckets"))
	list, err := h.files.Listening(r.Context(), files.ListeningQuery{FileID: q.Get("file"), Namespace: q.Get("namespace"), Since: since, Buckets: buckets})
	if list == nil {
		list = []files.FileListening{}
	}
	respond(w, http.StatusOK, map[string]any{"files": list}, err)
}
