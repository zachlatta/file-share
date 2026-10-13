package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const secret = "correct-horse-battery-staple-0123456789"

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestService(t *testing.T) (*Service, *http.ServeMux, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	s := NewService(Config{Secret: secret, BaseURL: "https://files.example.com", Now: c.now})
	mux := http.NewServeMux()
	s.RegisterHandlers(mux)
	mux.Handle("/mcp", s.RequireBearer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("client=" + ClientName(r.Context())))
	})))
	mux.Handle("/api/ping", s.RequireStaticBearer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("client=" + ClientName(r.Context())))
	})))
	return s, mux, c
}

func do(t *testing.T, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func form(method, target string, values url.Values) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func register(t *testing.T, mux http.Handler, redirect string) string {
	t.Helper()
	body := `{"client_name":"Claude","redirect_uris":["` + redirect + `"],"grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"none"}`
	rec := do(t, mux, httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.ClientID == "" {
		t.Fatalf("register response %s (%v)", rec.Body, err)
	}
	return out.ClientID
}

const verifier = "0123456789012345678901234567890123456789012-verifier"

func challenge() string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeValues(clientID, redirect string) url.Values {
	return url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"code_challenge":        {challenge()},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
	}
}

func authorize(t *testing.T, mux http.Handler, clientID, redirect string) string {
	t.Helper()
	values := authorizeValues(clientID, redirect)
	values.Set("secret_token", secret)
	values.Set("client_name", "claude-desktop")
	rec := do(t, mux, form(http.MethodPost, "/oauth/authorize", values))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status %d: %s", rec.Code, rec.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("state") != "xyz" {
		t.Fatalf("state not echoed: %s", loc)
	}
	return loc.Query().Get("code")
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

func exchange(t *testing.T, mux http.Handler, values url.Values) (*httptest.ResponseRecorder, tokens) {
	t.Helper()
	rec := do(t, mux, form(http.MethodPost, "/oauth/token", values))
	var out tokens
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func callMCP(t *testing.T, mux http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return do(t, mux, req)
}

func TestFullOAuthFlowWithSecretToken(t *testing.T) {
	_, mux, _ := newTestService(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	clientID := register(t, mux, redirect)

	page := do(t, mux, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeValues(clientID, redirect).Encode(), nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `name="secret_token"`) || !strings.Contains(page.Body.String(), `name="client_name"`) {
		t.Fatalf("authorize page: %d %s", page.Code, page.Body)
	}

	code := authorize(t, mux, clientID, redirect)
	rec, tok := exchange(t, mux, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier},
	})
	if rec.Code != http.StatusOK || tok.AccessToken == "" || tok.RefreshToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("token exchange: %d %s", rec.Code, rec.Body)
	}
	if got := callMCP(t, mux, tok.AccessToken); got.Code != http.StatusOK || got.Body.String() != "client=claude-desktop" {
		t.Fatalf("mcp with token: %d %s", got.Code, got.Body)
	}

	// Codes are single use.
	if rec, _ := exchange(t, mux, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier},
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed code accepted: %d", rec.Code)
	}

	// Refresh works and yields a working access token.
	rec, refreshed := exchange(t, mux, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {clientID}})
	if rec.Code != http.StatusOK || refreshed.AccessToken == "" {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body)
	}
	if got := callMCP(t, mux, refreshed.AccessToken); got.Code != http.StatusOK {
		t.Fatalf("mcp with refreshed token: %d", got.Code)
	}
	// A refresh token is not an access token.
	if got := callMCP(t, mux, tok.RefreshToken); got.Code != http.StatusUnauthorized {
		t.Fatalf("refresh token used as access token: %d", got.Code)
	}
}

func TestAuthorizeRejectsWrongSecret(t *testing.T) {
	_, mux, _ := newTestService(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	clientID := register(t, mux, redirect)
	values := authorizeValues(clientID, redirect)
	values.Set("secret_token", "nope")
	values.Set("client_name", "claude")
	if rec := do(t, mux, form(http.MethodPost, "/oauth/authorize", values)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", rec.Code)
	}
}

func TestAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	_, mux, _ := newTestService(t)
	clientID := register(t, mux, "https://claude.ai/api/mcp/auth_callback")
	values := authorizeValues(clientID, "https://evil.example.com/cb")
	values.Set("secret_token", secret)
	values.Set("client_name", "claude")
	if rec := do(t, mux, form(http.MethodPost, "/oauth/authorize", values)); rec.Code != http.StatusBadRequest {
		t.Fatalf("foreign redirect: %d", rec.Code)
	}
}

func TestLoopbackRedirectMayChangePort(t *testing.T) {
	_, mux, _ := newTestService(t)
	clientID := register(t, mux, "http://127.0.0.1:33418/callback")
	values := authorizeValues(clientID, "http://127.0.0.1:50000/callback")
	values.Set("secret_token", secret)
	values.Set("client_name", "codex")
	if rec := do(t, mux, form(http.MethodPost, "/oauth/authorize", values)); rec.Code != http.StatusFound {
		t.Fatalf("loopback port change: %d %s", rec.Code, rec.Body)
	}
}

func TestPKCEMustMatch(t *testing.T) {
	_, mux, _ := newTestService(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	clientID := register(t, mux, redirect)
	code := authorize(t, mux, clientID, redirect)
	rec, _ := exchange(t, mux, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {strings.Repeat("x", 50)},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad verifier accepted: %d", rec.Code)
	}
}

func TestAccessTokenExpires(t *testing.T) {
	_, mux, c := newTestService(t)
	redirect := "https://claude.ai/api/mcp/auth_callback"
	clientID := register(t, mux, redirect)
	code := authorize(t, mux, clientID, redirect)
	_, tok := exchange(t, mux, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier},
	})
	c.t = c.t.Add(25 * time.Hour)
	if got := callMCP(t, mux, tok.AccessToken); got.Code != http.StatusUnauthorized {
		t.Fatalf("expired token accepted: %d", got.Code)
	}
	// The refresh token still works after the access token expires.
	if rec, _ := exchange(t, mux, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}}); rec.Code != http.StatusOK {
		t.Fatalf("refresh after access expiry: %d", rec.Code)
	}
}

func TestTokensFromAnotherSecretAreRejected(t *testing.T) {
	_, mux, _ := newTestService(t)
	other := NewService(Config{Secret: "a-completely-different-secret-value-xx", BaseURL: "https://files.example.com"})
	forged, err := other.sign(signedPayload{Type: "access", ClientName: "x", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if got := callMCP(t, mux, forged); got.Code != http.StatusUnauthorized {
		t.Fatalf("forged token accepted: %d", got.Code)
	}
}

func TestUnauthenticatedMCPAdvertisesResourceMetadata(t *testing.T) {
	_, mux, _ := newTestService(t)
	rec := callMCP(t, mux, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	if h := rec.Header().Get("WWW-Authenticate"); !strings.Contains(h, "https://files.example.com/.well-known/oauth-protected-resource") {
		t.Fatalf("WWW-Authenticate = %q", h)
	}
	for _, path := range []string{
		"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp",
		"/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp",
		"/mcp/.well-known/oauth-protected-resource", "/.well-known/openid-configuration",
	} {
		rec := do(t, mux, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	rec = do(t, mux, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	var meta map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &meta)
	if meta["token_endpoint"] != "https://files.example.com/oauth/token" || meta["registration_endpoint"] != "https://files.example.com/oauth/register" {
		t.Fatalf("metadata = %v", meta)
	}
}

func TestStaticBearer(t *testing.T) {
	_, mux, _ := newTestService(t)
	call := func(header string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		return do(t, mux, req)
	}
	if rec := call("Bearer laptop:" + secret); rec.Code != http.StatusOK || rec.Body.String() != "client=laptop" {
		t.Fatalf("valid static bearer: %d %s", rec.Code, rec.Body)
	}
	for _, header := range []string{"", "Bearer " + secret, "Bearer laptop:wrong", "Basic abc", "Bearer bad:name:" + secret} {
		if rec := call(header); rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: %d", header, rec.Code)
		}
	}
}

func TestSignedURLs(t *testing.T) {
	s, _, c := newTestService(t)
	token := s.SignUpload(UploadGrant{Namespace: "ns", Filename: "a.txt"}, time.Hour)
	grant, err := s.VerifyUpload(token)
	if err != nil || grant.Namespace != "ns" || grant.Filename != "a.txt" {
		t.Fatalf("verify upload: %+v %v", grant, err)
	}
	c.t = c.t.Add(2 * time.Hour)
	if _, err := s.VerifyUpload(token); err == nil {
		t.Fatal("expired upload grant accepted")
	}
	if _, err := s.VerifyUpload(token + "x"); err == nil {
		t.Fatal("tampered upload grant accepted")
	}
}

func TestCheckSecret(t *testing.T) {
	s, _, _ := newTestService(t)
	if !s.CheckSecret(secret) || s.CheckSecret("") || s.CheckSecret(secret+"x") {
		t.Fatal("CheckSecret wrong")
	}
}

func TestSignedDownloadURLs(t *testing.T) {
	s, _, c := newTestService(t)
	token := s.SignDownload(DownloadGrant{FileID: "f1", Version: 3}, time.Hour)
	grant, err := s.VerifyDownload(token)
	if err != nil || grant.FileID != "f1" || grant.Version != 3 {
		t.Fatalf("verify download: %+v %v", grant, err)
	}
	if _, err := s.VerifyUpload(token); err == nil {
		t.Fatal("download token accepted as upload token")
	}
	c.t = c.t.Add(2 * time.Hour)
	if _, err := s.VerifyDownload(token); err == nil {
		t.Fatal("expired download grant accepted")
	}
}
