package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zachlatta/file-share/internal/files"
	"github.com/zachlatta/file-share/internal/hcauth"
)

// newEmailEnv runs against a fake Hack Club Auth where the code
// "code:<email>" signs in as <email>.
func newEmailEnv(t *testing.T) *env {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		email, ok := strings.CutPrefix(r.PostFormValue("code"), "code:")
		if !ok || r.PostFormValue("client_secret") != "csecret" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok:" + email})
	})
	mux.HandleFunc("GET /oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		email, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer tok:")
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "ident!x", "email": email, "email_verified": true})
	})
	hca := httptest.NewServer(mux)
	t.Cleanup(hca.Close)
	return newEnvWith(t, hcauth.New(hcauth.Config{
		ClientID: "cid", ClientSecret: "csecret", BaseURL: hca.URL,
		RedirectURL: "https://files.example.com/oauth/callback",
	}))
}

func (e *env) uploadFor(t *testing.T, name, body, password string, emails ...string) files.File {
	t.Helper()
	f, err := e.files.Upload(context.Background(), files.UploadInput{Name: name, Body: strings.NewReader(body), Size: -1, Password: password, AllowedEmails: emails})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func get(e *env, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return e.do(req)
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// signIn runs the whole Hack Club Auth flow from a file's gate page and
// returns the session cookie it sets.
func signIn(t *testing.T, e *env, f files.File, email string) *http.Cookie {
	t.Helper()
	start := get(e, "/oauth/hackclub?next="+url.QueryEscape(urlPath(f)))
	if start.Code != http.StatusFound {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	authorize, _ := url.Parse(start.Header().Get("Location"))
	state := authorize.Query().Get("state")
	stateCookie := cookieNamed(start, stateCookieName)
	if state == "" || stateCookie == nil || !stateCookie.HttpOnly || !stateCookie.Secure {
		t.Fatalf("start: location %s cookie %+v", authorize, stateCookie)
	}
	cb := get(e, "/oauth/callback?code="+url.QueryEscape("code:"+email)+"&state="+url.QueryEscape(state), stateCookie)
	if cb.Code != http.StatusSeeOther || cb.Header().Get("Location") != urlPath(f) {
		t.Fatalf("callback: %d %q %s", cb.Code, cb.Header().Get("Location"), cb.Body)
	}
	session := cookieNamed(cb, sessionCookieName(f.Namespace))
	if session == nil || !session.HttpOnly || !session.Secure || session.Path != "/"+f.Namespace+"/" {
		t.Fatalf("session cookie: %+v", session)
	}
	return session
}

func TestEmailRestrictedFile(t *testing.T) {
	e := newEmailEnv(t)
	f := e.uploadFor(t, "plan.txt", "the plan", "", "zach@hackclub.com")

	rec := get(e, urlPath(f))
	body := rec.Body.String()
	if rec.Code != http.StatusUnauthorized || strings.Contains(body, "the plan") || strings.Contains(body, `name="password"`) ||
		!strings.Contains(body, "/oauth/hackclub?next="+url.QueryEscape(urlPath(f))) {
		t.Fatalf("gate: %d %s", rec.Code, body)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("gate cache-control = %q", cc)
	}
	// A password never opens an email-only file.
	if rec := get(e, urlPath(f)+"?password=anything"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("?password= on email-only file: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, urlPath(f), nil)
	req.SetBasicAuth("", "anything")
	if rec := e.do(req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("basic auth on email-only file: %d", rec.Code)
	}

	session := signIn(t, e, f, "Zach@HackClub.com")
	rec = get(e, urlPath(f), session)
	if rec.Code != 200 || rec.Body.String() != "the plan" || !strings.Contains(rec.Header().Get("Cache-Control"), "private") {
		t.Fatalf("signed in: %d %q", rec.Code, rec.Body)
	}

	// The wrong account gets a 403 that names it and offers a switch.
	other := signIn(t, e, f, "someone@example.com")
	rec = get(e, urlPath(f), other)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "someone@example.com") ||
		!strings.Contains(rec.Body.String(), "switch=1") || strings.Contains(rec.Body.String(), "the plan") {
		t.Fatalf("wrong account: %d %s", rec.Code, rec.Body)
	}

	// The session works for other files in the namespace that allow the
	// email, and changes to the allow list apply immediately.
	g, err := e.files.Upload(context.Background(), files.UploadInput{Namespace: f.Namespace, Name: "notes.txt", Body: strings.NewReader("notes"), Size: -1, AllowedEmails: []string{"@hackclub.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if rec := get(e, urlPath(g), session); rec.Code != 200 {
		t.Fatalf("domain entry: %d", rec.Code)
	}
	if _, err := e.files.SetAllowedEmails(context.Background(), f.ID, []string{"friend@gmail.com"}); err != nil {
		t.Fatal(err)
	}
	if rec := get(e, urlPath(f), session); rec.Code != http.StatusForbidden {
		t.Fatalf("after removal from allow list: %d", rec.Code)
	}

	// A session cookie from one namespace does not open another.
	h := e.uploadFor(t, "elsewhere.txt", "x", "", "zach@hackclub.com")
	forged := &http.Cookie{Name: sessionCookieName(h.Namespace), Value: session.Value}
	if rec := get(e, urlPath(h), forged); rec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-namespace session: %d", rec.Code)
	}
}

func TestEmailCallbackRejectsForgedOrForeignState(t *testing.T) {
	e := newEmailEnv(t)
	f := e.uploadFor(t, "plan.txt", "the plan", "", "zach@hackclub.com")
	start := get(e, "/oauth/hackclub?next="+url.QueryEscape(urlPath(f)))
	authorize, _ := url.Parse(start.Header().Get("Location"))
	state := url.QueryEscape(authorize.Query().Get("state"))
	code := url.QueryEscape("code:zach@hackclub.com")

	// Without the browser's state cookie (login CSRF), or with another one.
	if rec := get(e, "/oauth/callback?code="+code+"&state="+state); rec.Code != http.StatusBadRequest || cookieNamed(rec, sessionCookieName(f.Namespace)) != nil {
		t.Fatalf("no state cookie: %d", rec.Code)
	}
	wrong := &http.Cookie{Name: stateCookieName, Value: "not-the-nonce"}
	if rec := get(e, "/oauth/callback?code="+code+"&state="+state, wrong); rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong state cookie: %d", rec.Code)
	}
	// Tampered state, a rejected code, and a provider error.
	stateCookie := cookieNamed(start, stateCookieName)
	if rec := get(e, "/oauth/callback?code="+code+"&state="+state+"x", stateCookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("tampered state: %d", rec.Code)
	}
	if rec := get(e, "/oauth/callback?code=bogus&state="+state, stateCookie); rec.Code != http.StatusBadGateway {
		t.Fatalf("bad code: %d", rec.Code)
	}
	if rec := get(e, "/oauth/callback?error=access_denied&state="+state, stateCookie); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "cancelled") {
		t.Fatalf("provider error: %d %s", rec.Code, rec.Body)
	}
}

func TestEmailLoginOnlyReturnsToFilePaths(t *testing.T) {
	e := newEmailEnv(t)
	f := e.uploadFor(t, "plan.txt", "x", "", "zach@hackclub.com")
	for _, next := range []string{"", "https://evil.example/", "//evil.example/x", "/not-a-uuid/x", "/" + f.Namespace, "/oauth/token", `/\evil.example`} {
		if rec := get(e, "/oauth/hackclub?next="+url.QueryEscape(next)); rec.Code != http.StatusBadRequest {
			t.Errorf("next=%q: %d %s", next, rec.Code, rec.Header().Get("Location"))
		}
	}
	// Nested paths, escapes and a namespace index are fine.
	for _, next := range []string{"/" + f.Namespace + "/", "/" + f.Namespace + "/a%20b/c.txt"} {
		if rec := get(e, "/oauth/hackclub?next="+url.QueryEscape(next)); rec.Code != http.StatusFound {
			t.Errorf("next=%q: %d %s", next, rec.Code, rec.Body)
		}
	}
	rec := get(e, "/oauth/hackclub?switch=1&next="+url.QueryEscape(urlPath(f)))
	if u, _ := url.Parse(rec.Header().Get("Location")); u.Query().Get("prompt") != "login" {
		t.Fatalf("switch account: %s", rec.Header().Get("Location"))
	}
}

func TestPasswordOrEmailEitherOpens(t *testing.T) {
	e := newEmailEnv(t)
	f := e.uploadFor(t, "both.txt", "both", "opensesame", "zach@hackclub.com")
	rec := get(e, urlPath(f))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `name="password"`) || !strings.Contains(rec.Body.String(), "/oauth/hackclub") {
		t.Fatalf("gate should offer both: %d %s", rec.Code, rec.Body)
	}
	if rec := get(e, urlPath(f)+"?password=opensesame"); rec.Code != 200 {
		t.Fatalf("password: %d", rec.Code)
	}
	if rec := get(e, urlPath(f), signIn(t, e, f, "zach@hackclub.com")); rec.Code != 200 {
		t.Fatalf("email: %d", rec.Code)
	}
	// The wrong account still sees the password form.
	rec = get(e, urlPath(f), signIn(t, e, f, "someone@example.com"))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `name="password"`) {
		t.Fatalf("wrong account with password: %d %s", rec.Code, rec.Body)
	}
}

func TestEmailLoginDisabledWithoutHCA(t *testing.T) {
	e := newEnv(t)
	if rec := get(e, "/oauth/hackclub?next=/x/y"); rec.Code != http.StatusNotFound {
		t.Fatalf("start: %d", rec.Code)
	}
	if rec := get(e, "/oauth/callback?code=x&state=y"); rec.Code != http.StatusNotFound {
		t.Fatalf("callback: %d", rec.Code)
	}
}

func TestAPIUploadWithEmails(t *testing.T) {
	e := newEmailEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/api/files?name=a.txt&emails="+url.QueryEscape("zach@hackclub.com, @example.org"), strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer curl:"+secret)
	rec := e.do(req)
	if f := decodeFile(t, rec); rec.Code != http.StatusCreated || strings.Join(f.AllowedEmails, ",") != "@example.org,zach@hackclub.com" {
		t.Fatalf("api upload: %d %s", rec.Code, rec.Body)
	}
	body, ctype := multipartBody(t, "b.txt", "y", map[string]string{"emails": "friend@gmail.com"})
	req = httptest.NewRequest(http.MethodPost, "/api/files", body)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Authorization", "Bearer curl:"+secret)
	rec = e.do(req)
	if f := decodeFile(t, rec); rec.Code != http.StatusCreated || strings.Join(f.AllowedEmails, ",") != "friend@gmail.com" {
		t.Fatalf("multipart upload: %d %s", rec.Code, rec.Body)
	}
}
