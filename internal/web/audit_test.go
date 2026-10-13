package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zachlatta/file-share/internal/auth"
	"github.com/zachlatta/file-share/internal/files"
)

func (e *env) events(t *testing.T) []files.AccessEvent {
	t.Helper()
	list, err := e.files.ListAccess(context.Background(), files.AccessQuery{})
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func visitor(method, target string, body string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.RemoteAddr = "10.0.0.5:4321"
	req.Header.Set("CF-Connecting-IP", "203.0.113.9")
	req.Header.Set("CF-IPCountry", "CA")
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	req.Header.Set("User-Agent", "TestBrowser/1.0")
	req.Header.Set("Referer", "https://chat.example/thread?token=leaky#frag")
	return req
}

func TestAuditLogsPasswordAccess(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "secret.txt", "classified", "opensesame")
	e.do(visitor(http.MethodGet, urlPath(f), ""))                            // denied
	e.do(visitor(http.MethodPost, urlPath(f), "password=wrong-guess"))       // wrong_password
	rec := e.do(visitor(http.MethodPost, urlPath(f), "password=opensesame")) // unlock
	req := visitor(http.MethodGet, urlPath(f), "")
	req.AddCookie(rec.Result().Cookies()[0])
	e.do(req)                                                                     // view via cookie
	e.do(visitor(http.MethodGet, urlPath(f)+"?password=opensesame&download", "")) // view via query
	req = visitor(http.MethodGet, urlPath(f), "")
	req.SetBasicAuth("", "opensesame")
	e.do(req) // view via basic auth
	// Continuations of a range request are not separate views.
	req = visitor(http.MethodGet, urlPath(f)+"?password=opensesame", "")
	req.Header.Set("Range", "bytes=5-")
	e.do(req)

	got := e.events(t)
	var summary []string
	for i := len(got) - 1; i >= 0; i-- {
		summary = append(summary, got[i].Event+":"+got[i].Via)
	}
	want := "denied: wrong_password:password_form unlock:password_form view:password_cookie view:password_query view:basic_auth"
	if strings.Join(summary, " ") != want {
		t.Fatalf("events = %q\nwant     %q", strings.Join(summary, " "), want)
	}
	v := got[0]
	if v.FileID != f.ID || v.Name != "secret.txt" || v.Namespace != f.Namespace || v.Version != 1 || v.Status != 200 ||
		v.IP != "203.0.113.9" || v.Country != "CA" || v.UserAgent != "TestBrowser/1.0" || v.RemoteAddr != "10.0.0.5" ||
		v.ForwardedFor != "203.0.113.9, 10.0.0.1" || v.Referer != "https://chat.example/thread" {
		t.Fatalf("view event = %+v", v)
	}
	if got[len(got)-1].Status != http.StatusUnauthorized {
		t.Fatalf("denied status = %d", got[len(got)-1].Status)
	}
	// Passwords and query strings never reach the log.
	data, _ := json.Marshal(got)
	for _, leak := range []string{"opensesame", "wrong-guess", "leaky"} {
		if strings.Contains(string(data), leak) {
			t.Fatalf("audit log contains %q: %s", leak, data)
		}
	}
}

func TestAuditLogsEmailAccessAndSignIn(t *testing.T) {
	e := newEmailEnv(t)
	f := e.uploadFor(t, "plan.txt", "the plan", "", "zach@hackclub.com")
	session := signIn(t, e, f, "zach@hackclub.com")
	req := visitor(http.MethodGet, urlPath(f), "")
	req.AddCookie(session)
	e.do(req)
	other := signIn(t, e, f, "someone@example.com")
	req = visitor(http.MethodGet, urlPath(f), "")
	req.AddCookie(other)
	e.do(req)

	got := e.events(t)
	var summary []string
	for i := len(got) - 1; i >= 0; i-- {
		summary = append(summary, got[i].Event+":"+got[i].Email)
	}
	want := "sign_in:zach@hackclub.com view:zach@hackclub.com sign_in:someone@example.com denied:someone@example.com"
	if strings.Join(summary, " ") != want {
		t.Fatalf("events = %q\nwant     %q", strings.Join(summary, " "), want)
	}
	if got[0].Status != http.StatusForbidden || got[2].Via != "email" || got[3].FileID != f.ID {
		t.Fatalf("events = %+v", got)
	}
}

func TestAuditSkipsPublicFilesAndLogsDownloadURLs(t *testing.T) {
	e := newEnv(t)
	pub := e.upload(t, "public.txt", "hi", "")
	e.do(visitor(http.MethodGet, urlPath(pub), ""))
	e.do(httptest.NewRequest(http.MethodGet, "/download/"+e.auth.SignDownload(auth.DownloadGrant{FileID: pub.ID}, time.Hour), nil))
	if got := e.events(t); len(got) != 0 {
		t.Fatalf("public file access logged: %+v", got)
	}
	f := e.upload(t, "secret.txt", "classified", "opensesame")
	e.do(visitor(http.MethodGet, "/download/"+e.auth.SignDownload(auth.DownloadGrant{FileID: f.ID}, time.Hour), ""))
	if got := e.events(t); len(got) != 1 || got[0].Event != "view" || got[0].Via != "download_url" || got[0].FileID != f.ID {
		t.Fatalf("download URL access: %+v", got)
	}
}

func TestClientIPFallsBackToSocketAddress(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[2001:db8::1]:443"
	r.Header.Set("CF-Connecting-IP", "not an ip")
	if ip := clientIP(r, "CF-Connecting-IP"); ip != "2001:db8::1" {
		t.Fatalf("clientIP = %q", ip)
	}
	r.Header.Set("CF-Connecting-IP", "198.51.100.7")
	if ip := clientIP(r, ""); ip != "2001:db8::1" {
		t.Fatalf("header must be ignored unless configured: %q", ip)
	}
	if ip := clientIP(r, "CF-Connecting-IP"); ip != "198.51.100.7" {
		t.Fatalf("clientIP = %q", ip)
	}
}

func adminGet(e *env, target, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return e.do(req)
}

func TestAdminAPI(t *testing.T) {
	e := newEmailEnv(t)
	f := e.uploadFor(t, "plan.txt", "the plan", "pw-123", "zach@hackclub.com")
	e.upload(t, "public.txt", "x", "")
	e.do(visitor(http.MethodGet, urlPath(f), ""))
	e.do(visitor(http.MethodGet, urlPath(f)+"?password=pw-123", ""))

	for _, path := range []string{"/api/admin/access", "/api/admin/files"} {
		for _, token := range []string{"", "wrong", secret, "curl:" + secret} {
			if rec := adminGet(e, path, token); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s with %q: %d", path, token, rec.Code)
			}
		}
	}
	// The admin token is not an API credential either.
	if rec := adminGet(e, "/api/files", "curl:"+adminToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin token accepted by the file API: %d", rec.Code)
	}

	rec := adminGet(e, "/api/admin/access?limit=1", adminToken)
	var access struct {
		Events []files.AccessEvent `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &access); err != nil || rec.Code != 200 || len(access.Events) != 1 || access.Events[0].Event != "view" {
		t.Fatalf("access: %d %s", rec.Code, rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("cache-control = %q", cc)
	}
	rec = adminGet(e, fmt.Sprintf("/api/admin/access?before=%d&file=%s&event=denied", access.Events[0].ID, f.ID), adminToken)
	if err := json.Unmarshal(rec.Body.Bytes(), &access); err != nil || len(access.Events) != 1 || access.Events[0].Event != "denied" {
		t.Fatalf("filtered access: %d %s", rec.Code, rec.Body)
	}
	rec = adminGet(e, "/api/admin/access?q="+url.QueryEscape("203.0.113"), adminToken)
	if err := json.Unmarshal(rec.Body.Bytes(), &access); err != nil || len(access.Events) != 2 {
		t.Fatalf("search: %s", rec.Body)
	}

	rec = adminGet(e, "/api/admin/files", adminToken)
	var list struct {
		Files []files.RestrictedFile `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Files) != 1 || list.Files[0].Views != 1 || list.Files[0].Denied != 1 {
		t.Fatalf("files: %d %s", rec.Code, rec.Body)
	}
}

func TestAdminPage(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "secret.txt", "classified", "opensesame")
	e.do(visitor(http.MethodGet, urlPath(f), ""))
	rec := e.do(httptest.NewRequest(http.MethodGet, "/admin", nil))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `type="password"`) || strings.Contains(body, "secret.txt") || strings.Contains(body, "203.0.113") {
		t.Fatalf("admin page: %d %s", rec.Code, body)
	}
	h := rec.Header()
	if h.Get("Cross-Origin-Opener-Policy") != "same-origin" || !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		!strings.Contains(h.Get("Content-Security-Policy"), "script-src 'self'") || h.Get("X-Frame-Options") != "DENY" ||
		!strings.Contains(h.Get("Cache-Control"), "no-store") || h.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("admin page headers: %v", h)
	}
	// Login must never rely on a cookie: an uploaded page on this origin
	// could otherwise fetch the audit log with the admin's cookies.
	if len(rec.Result().Cookies()) != 0 || strings.Contains(body, "localStorage") || strings.Contains(body, "sessionStorage") || strings.Contains(body, "document.cookie") {
		t.Fatalf("admin page persists credentials")
	}
	js := e.do(httptest.NewRequest(http.MethodGet, "/admin/app.js", nil))
	if js.Code != 200 || !strings.HasPrefix(js.Header().Get("Content-Type"), "text/javascript") ||
		strings.Contains(js.Body.String(), "localStorage") || strings.Contains(js.Body.String(), "sessionStorage") ||
		strings.Contains(js.Body.String(), "document.cookie") || strings.Contains(js.Body.String(), "innerHTML") {
		t.Fatalf("admin script: %d %q", js.Code, js.Header().Get("Content-Type"))
	}
}

func TestAdminDisabledWithoutToken(t *testing.T) {
	e := newEnv(t)
	mux := http.NewServeMux()
	New(Config{Files: e.files, Auth: e.auth, Version: "test"}).Register(mux)
	for _, path := range []string{"/admin", "/admin/app.js", "/api/admin/access", "/api/admin/files"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer ")
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}
