package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zachlatta/file-share/internal/auth"
	"github.com/zachlatta/file-share/internal/blob"
	"github.com/zachlatta/file-share/internal/files"
	"github.com/zachlatta/file-share/internal/hcauth"
	"github.com/zachlatta/file-share/internal/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

const (
	secret     = "web-test-secret-0123456789-abcdef"
	adminToken = "web-test-admin-token-0123456789-xyz"
)

type env struct {
	files   *files.Service
	auth    *auth.Service
	handler http.Handler
	limiter *failureLimiter
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, nil)
}

// newEnvWith builds a handler; hca, if set, enables Hack Club Auth sign-in.
func newEnvWith(t *testing.T, hca *hcauth.Client) *env {
	t.Helper()
	svc, err := files.Open(context.Background(), files.Config{
		DatabaseURL: pgtest.New(t), Blobs: blob.NewMemory(), BaseURL: "https://files.example.com",
		Retention: 30 * 24 * time.Hour, MaxBytes: 1 << 20, EmailLogin: hca != nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	a := auth.NewService(auth.Config{Secret: secret, BaseURL: "https://files.example.com"})
	mux := http.NewServeMux()
	h := New(Config{Files: svc, Auth: a, HCA: hca, Version: "test", AdminToken: adminToken, ClientIPHeader: "CF-Connecting-IP"})
	h.Register(mux)
	return &env{files: svc, auth: a, handler: mux, limiter: h.passwords}
}

func (e *env) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func (e *env) upload(t *testing.T, name, body, password string) files.File {
	t.Helper()
	f, err := e.files.Upload(context.Background(), files.UploadInput{Name: name, Body: strings.NewReader(body), Size: -1, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func urlPath(f files.File) string { return strings.TrimPrefix(f.URL, "https://files.example.com") }

func TestServesFiles(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "hello world.txt", "hello there", "")
	rec := e.do(httptest.NewRequest(http.MethodGet, urlPath(f), nil))
	if rec.Code != 200 || rec.Body.String() != "hello there" {
		t.Fatalf("get: %d %q", rec.Code, rec.Body)
	}
	if rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", rec.Header())
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "inline") || rec.Header().Get("ETag") == "" {
		t.Fatalf("headers: %v", rec.Header())
	}
	// Range requests.
	req := httptest.NewRequest(http.MethodGet, urlPath(f), nil)
	req.Header.Set("Range", "bytes=6-")
	if rec := e.do(req); rec.Code != http.StatusPartialContent || rec.Body.String() != "there" {
		t.Fatalf("range: %d %q", rec.Code, rec.Body)
	}
	// Download disposition.
	if rec := e.do(httptest.NewRequest(http.MethodGet, urlPath(f)+"?download=1", nil)); !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("download disposition: %q", rec.Header().Get("Content-Disposition"))
	}
	// Unknown namespace or name.
	for _, p := range []string{"/" + f.Namespace + "/nope.txt", "/00000000-0000-4000-8000-000000000000/hello%20world.txt", "/not-a-uuid/x"} {
		if rec := e.do(httptest.NewRequest(http.MethodGet, p, nil)); rec.Code != 404 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	// Deleted files disappear.
	_, _ = e.files.Delete(context.Background(), f.ID)
	if rec := e.do(httptest.NewRequest(http.MethodGet, urlPath(f), nil)); rec.Code != 404 {
		t.Fatalf("deleted: %d", rec.Code)
	}
}

func TestHTMLRunsNormallyAndIndexServed(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "index.html", "<h1>site</h1>", "")
	rec := e.do(httptest.NewRequest(http.MethodGet, "/"+f.Namespace+"/", nil))
	if rec.Code != 200 || rec.Body.String() != "<h1>site</h1>" {
		t.Fatalf("index: %d %q", rec.Code, rec.Body)
	}
	// Uploaded pages must run as ordinary pages: a CSP sandbox gives them an
	// opaque origin, which disables Cache Storage and broke a MapLibre map.
	if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "sandbox") {
		t.Fatalf("html is sandboxed: csp = %q", csp)
	}
	if rec := e.do(httptest.NewRequest(http.MethodGet, "/"+f.Namespace, nil)); rec.Code != http.StatusMovedPermanently {
		t.Fatalf("namespace without slash: %d", rec.Code)
	}
}

func TestPasswordProtectedFiles(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "secret.txt", "classified", "opensesame")
	rec := e.do(httptest.NewRequest(http.MethodGet, urlPath(f), nil))
	if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "classified") || !strings.Contains(rec.Body.String(), `name="password"`) {
		t.Fatalf("no password: %d %q", rec.Code, rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("cache-control = %q", cc)
	}
	// Wrong password via form.
	post := func(pw string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, urlPath(f), strings.NewReader(url.Values{"password": {pw}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return e.do(req)
	}
	if rec := post("nope"); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Wrong password") {
		t.Fatalf("wrong password: %d", rec.Code)
	}
	rec = post("opensesame")
	if rec.Code != http.StatusSeeOther || len(rec.Result().Cookies()) != 1 {
		t.Fatalf("right password: %d %v", rec.Code, rec.Result().Cookies())
	}
	cookie := rec.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure {
		t.Fatalf("cookie flags: %+v", cookie)
	}
	req := httptest.NewRequest(http.MethodGet, urlPath(f), nil)
	req.AddCookie(cookie)
	if rec := e.do(req); rec.Code != 200 || rec.Body.String() != "classified" || !strings.Contains(rec.Header().Get("Cache-Control"), "private") {
		t.Fatalf("with cookie: %d %q", rec.Code, rec.Body)
	}
	// Query parameter and basic auth work for scripts.
	if rec := e.do(httptest.NewRequest(http.MethodGet, urlPath(f)+"?password=opensesame", nil)); rec.Code != 200 {
		t.Fatalf("query password: %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, urlPath(f), nil)
	req.SetBasicAuth("", "opensesame")
	if rec := e.do(req); rec.Code != 200 {
		t.Fatalf("basic auth: %d", rec.Code)
	}
	// Changing the password invalidates old cookies.
	_, _ = e.files.SetPassword(context.Background(), f.ID, "newpass")
	req = httptest.NewRequest(http.MethodGet, urlPath(f), nil)
	req.AddCookie(cookie)
	if rec := e.do(req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale cookie: %d", rec.Code)
	}
	// A cookie for one file does not open another.
	g := e.upload(t, "other.txt", "other secret", "opensesame")
	req = httptest.NewRequest(http.MethodGet, urlPath(g), nil)
	req.AddCookie(&http.Cookie{Name: cookieName(g.ID), Value: cookie.Value})
	if rec := e.do(req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-file cookie: %d", rec.Code)
	}
}

func multipartBody(t *testing.T, filename, content string, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	part, _ := w.CreateFormFile("file", filename)
	_, _ = io.WriteString(part, content)
	_ = w.Close()
	return &buf, w.FormDataContentType()
}

func decodeFile(t *testing.T, rec *httptest.ResponseRecorder) files.File {
	t.Helper()
	var f files.File
	if err := json.Unmarshal(rec.Body.Bytes(), &f); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return f
}

func TestAPIUploadReplaceDelete(t *testing.T) {
	e := newEnv(t)
	authz := "Bearer curl:" + secret

	// Multipart upload.
	body, ct := multipartBody(t, "photo.png", "\x89PNG fake", map[string]string{"password": "pw"})
	req := httptest.NewRequest(http.MethodPost, "/api/files", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", authz)
	rec := e.do(req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("multipart upload: %d %s", rec.Code, rec.Body)
	}
	f := decodeFile(t, rec)
	if f.Name != "photo.png" || f.ContentType != "image/png" || !f.HasPassword {
		t.Fatalf("uploaded = %+v", f)
	}

	// Raw upload into the same namespace.
	req = httptest.NewRequest(http.MethodPost, "/api/files?name=notes/a.txt&namespace="+f.Namespace, strings.NewReader("raw body"))
	req.Header.Set("Authorization", authz)
	rec = e.do(req)
	if rec.Code != http.StatusCreated || decodeFile(t, rec).Namespace != f.Namespace {
		t.Fatalf("raw upload: %d %s", rec.Code, rec.Body)
	}
	// Duplicate name conflicts.
	req = httptest.NewRequest(http.MethodPost, "/api/files?name=notes/a.txt&namespace="+f.Namespace, strings.NewReader("again"))
	req.Header.Set("Authorization", authz)
	if rec := e.do(req); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", rec.Code)
	}

	// Replace.
	req = httptest.NewRequest(http.MethodPut, "/api/files/"+f.ID+"/content", strings.NewReader("\x89PNG v2"))
	req.Header.Set("Authorization", authz)
	rec = e.do(req)
	if rec.Code != 200 || decodeFile(t, rec).Version != 2 {
		t.Fatalf("replace: %d %s", rec.Code, rec.Body)
	}

	// List and get.
	req = httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", authz)
	rec = e.do(req)
	var list struct{ Files []files.File }
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != 200 || len(list.Files) != 2 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}

	// Delete.
	req = httptest.NewRequest(http.MethodDelete, "/api/files/"+f.ID, nil)
	req.Header.Set("Authorization", authz)
	if rec := e.do(req); rec.Code != 200 || decodeFile(t, rec).DeletedAt == nil {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}

	// Unauthenticated calls are refused.
	if rec := e.do(httptest.NewRequest(http.MethodPost, "/api/files?name=x", strings.NewReader("x"))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous upload: %d", rec.Code)
	}
}

func TestAPIMultipartFieldsAfterFile(t *testing.T) {
	e := newEnv(t)
	// curl -F file=@x -F password=pw sends the password after the file part.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, _ := w.CreateFormFile("file", "late.txt")
	_, _ = io.WriteString(part, "late fields")
	_ = w.WriteField("password", "pw")
	_ = w.WriteField("name", "renamed.txt")
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/files", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer curl:"+secret)
	rec := e.do(req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	f := decodeFile(t, rec)
	if !f.HasPassword || f.Name != "renamed.txt" || f.Size != 11 {
		t.Fatalf("fields after the file part were ignored: %+v", f)
	}
}

func TestAPIRejectsOversizeUpload(t *testing.T) {
	e := newEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/api/files?name=big.bin", strings.NewReader(strings.Repeat("x", 1<<20+10)))
	req.Header.Set("Authorization", "Bearer curl:"+secret)
	if rec := e.do(req); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: %d %s", rec.Code, rec.Body)
	}
}

// link makes a single-use upload URL path, as create_upload_url does.
func (e *env) link(t *testing.T, in files.UploadLinkInput) string {
	t.Helper()
	in.ExpiresAt = time.Now().Add(time.Hour)
	link, err := e.files.CreateUploadLink(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return "/upload/" + e.auth.SignUpload(link.ID, time.Hour)
}

func TestSignedUploadURL(t *testing.T) {
	e := newEnv(t)
	path := e.link(t, files.UploadLinkInput{Name: "video.mp4", Client: "agent", Password: "pw"})
	rec := e.do(httptest.NewRequest(http.MethodPut, path, strings.NewReader("fake mp4 bytes")))
	if rec.Code != http.StatusCreated {
		t.Fatalf("signed upload: %d %s", rec.Code, rec.Body)
	}
	f := decodeFile(t, rec)
	if f.Name != "video.mp4" || f.ContentType != "video/mp4" || !f.HasPassword {
		t.Fatalf("file = %+v", f)
	}
	// One-off: the link stops working once used.
	if rec := e.do(httptest.NewRequest(http.MethodPut, path, strings.NewReader("again"))); rec.Code != http.StatusGone {
		t.Fatalf("reused link: %d %s", rec.Code, rec.Body)
	}
	// Replace link; multipart works too.
	path = e.link(t, files.UploadLinkInput{FileID: f.ID})
	body, ct := multipartBody(t, "ignored.mp4", "v2 bytes", nil)
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", ct)
	if rec := e.do(req); rec.Code != 200 || decodeFile(t, rec).Version != 2 {
		t.Fatalf("signed replace: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(httptest.NewRequest(http.MethodPut, "/upload/garbage", strings.NewReader("x"))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}
}

func TestSignedUploadURLWithoutName(t *testing.T) {
	e := newEnv(t)
	path := e.link(t, files.UploadLinkInput{})
	// Access settings belong to the link, not the request.
	body, ct := multipartBody(t, "photo.png", "\x89PNG fake", map[string]string{"password": "pw"})
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", ct)
	if rec := e.do(req); rec.Code != http.StatusBadRequest {
		t.Fatalf("password in request: %d %s", rec.Code, rec.Body)
	}
	body, ct = multipartBody(t, "photo.png", "\x89PNG fake", nil)
	req = httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", ct)
	rec := e.do(req)
	if rec.Code != http.StatusCreated || decodeFile(t, rec).Name != "photo.png" {
		t.Fatalf("multipart name: %d %s", rec.Code, rec.Body)
	}
	path = e.link(t, files.UploadLinkInput{})
	if rec := e.do(httptest.NewRequest(http.MethodPut, path+"?name=a%20b.txt", strings.NewReader("x"))); rec.Code != http.StatusCreated || decodeFile(t, rec).Name != "a b.txt" {
		t.Fatalf("raw ?name=: %d %s", rec.Code, rec.Body)
	}
}

func TestSignedDownloadURL(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "doc.txt", "one", "pw")
	_, _ = e.files.Replace(context.Background(), f.ID, files.ReplaceInput{Body: strings.NewReader("two"), Size: -1})
	token := e.auth.SignDownload(auth.DownloadGrant{FileID: f.ID, Version: 1}, time.Hour)
	rec := e.do(httptest.NewRequest(http.MethodGet, "/download/"+token, nil))
	if rec.Code != 200 || rec.Body.String() != "one" {
		t.Fatalf("signed download of v1 (password bypassed by signature): %d %q", rec.Code, rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "private, no-store" {
		t.Fatalf("signed download cache-control = %q", cc)
	}
	_, _ = e.files.Delete(context.Background(), f.ID)
	if rec := e.do(httptest.NewRequest(http.MethodGet, "/download/"+token, nil)); rec.Code != 200 {
		t.Fatalf("signed download of deleted file should work for recovery: %d", rec.Code)
	}
}

func TestHealthAndHome(t *testing.T) {
	e := newEnv(t)
	rec := e.do(httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"storage":"ok"`) {
		t.Fatalf("healthz: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(httptest.NewRequest(http.MethodGet, "/", nil)); rec.Code != 200 {
		t.Fatalf("home: %d", rec.Code)
	}
}

func TestChunkedSignedUpload(t *testing.T) {
	e := newEnv(t)
	path := e.link(t, files.UploadLinkInput{})
	for i, chunk := range []string{"one-", "two-", "three"} {
		rec := e.do(httptest.NewRequest(http.MethodPut, fmt.Sprintf("%s?part=%d", path, i+1), strings.NewReader(chunk)))
		if rec.Code != http.StatusOK {
			t.Fatalf("part %d: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	if rec := e.do(httptest.NewRequest(http.MethodPost, path+"?complete=4&name=movie.mp4", nil)); rec.Code != http.StatusBadRequest {
		t.Fatalf("complete with missing part: %d", rec.Code)
	}
	rec := e.do(httptest.NewRequest(http.MethodPost, path+"?complete=3&name=movie.mp4", nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body)
	}
	f := decodeFile(t, rec)
	if f.Name != "movie.mp4" || f.Size != 13 || f.ContentType != "video/mp4" {
		t.Fatalf("file = %+v", f)
	}
	if got := e.do(httptest.NewRequest(http.MethodGet, urlPath(f), nil)); got.Body.String() != "one-two-three" {
		t.Fatalf("content = %q", got.Body)
	}
	if rec := e.do(httptest.NewRequest(http.MethodPut, path+"?part=1", strings.NewReader("x"))); rec.Code != http.StatusGone {
		t.Fatalf("part after use: %d", rec.Code)
	}
	// Chunked replace.
	path = e.link(t, files.UploadLinkInput{FileID: f.ID})
	_ = e.do(httptest.NewRequest(http.MethodPut, path+"?part=1", strings.NewReader("v2")))
	if rec := e.do(httptest.NewRequest(http.MethodPost, path+"?complete=1", nil)); rec.Code != 200 || decodeFile(t, rec).Version != 2 {
		t.Fatalf("chunked replace: %d %s", rec.Code, rec.Body)
	}
}
