// Package auth implements MCP OAuth for a single owner, ported from the
// personal data warehouse design: dynamic client registration, an authorize
// page that asks for the server's pre-shared secret token, and S256 PKCE.
//
// Everything is stateless. Client IDs, authorization codes, access tokens,
// refresh tokens and upload grants are HMAC-SHA256-signed JSON payloads keyed
// by the secret, so nothing about auth needs a database and rotating the
// secret revokes every outstanding credential at once. The only server-side
// state is an in-memory set of consumed authorization codes (single use).
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	scope         = "files"
	codeTTL       = 10 * time.Minute
	accessTTL     = 24 * time.Hour
	refreshTTL    = 365 * 24 * time.Hour
	maxClientName = 64
)

type Config struct {
	// Secret is the pre-shared token typed on the authorize page and used as
	// the HMAC key for every signed credential.
	Secret string
	// BaseURL is the public origin, e.g. https://files.zachlatta.com.
	BaseURL string
	Now     func() time.Time
	Logger  *slog.Logger
}

type Service struct {
	secret   []byte
	baseURL  string
	now      func() time.Time
	logger   *slog.Logger
	mu       sync.Mutex
	consumed map[string]int64
}

type signedPayload struct {
	Type         string   `json:"type"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	RedirectURI  string   `json:"redirect_uri,omitempty"`
	Challenge    string   `json:"code_challenge,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Namespace    string   `json:"namespace,omitempty"`
	Filename     string   `json:"filename,omitempty"`
	FileID       string   `json:"file_id,omitempty"`
	Version      int      `json:"version,omitempty"`
	Nonce        string   `json:"nonce,omitempty"`
	Exp          int64    `json:"exp,omitempty"`
	Iat          int64    `json:"iat,omitempty"`
}

func NewService(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{
		secret:   []byte(cfg.Secret),
		baseURL:  strings.TrimRight(cfg.BaseURL, "/"),
		now:      cfg.Now,
		logger:   cfg.Logger.With("component", "auth"),
		consumed: map[string]int64{},
	}
}

// CheckSecret reports whether value is the configured secret, in constant time.
func (s *Service) CheckSecret(value string) bool {
	if len(s.secret) == 0 || value == "" {
		return false
	}
	a := sha256.Sum256([]byte(value))
	b := sha256.Sum256(s.secret)
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func (s *Service) RegisterHandlers(mux *http.ServeMux) {
	// Clients derive discovery URLs from /mcp in several shapes (root,
	// RFC 8414/9728 path-inserted, path-appended, OIDC). Claude's connector
	// gives up if they 404, so every variant serves the same document.
	resourceMeta := http.HandlerFunc(s.protectedResourceMetadata)
	authMeta := http.HandlerFunc(s.authServerMetadata)
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/", "/mcp/.well-known/oauth-protected-resource"} {
		mux.Handle("GET "+p, resourceMeta)
	}
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/", "/mcp/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration", "/.well-known/openid-configuration/", "/mcp/.well-known/openid-configuration"} {
		mux.Handle("GET "+p, authMeta)
	}
	mux.HandleFunc("POST /oauth/register", s.register)
	mux.HandleFunc("GET /oauth/authorize", s.authorizePage)
	mux.HandleFunc("POST /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("GET /oauth/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}})
	})
}

func (s *Service) protectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.baseURL + "/mcp",
		"authorization_servers":    []string{s.baseURL},
		"scopes_supported":         []string{scope},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "file-share",
	})
}

func (s *Service) authServerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.baseURL,
		"authorization_endpoint":                s.baseURL + "/oauth/authorize",
		"token_endpoint":                        s.baseURL + "/oauth/token",
		"registration_endpoint":                 s.baseURL + "/oauth/register",
		"jwks_uri":                              s.baseURL + "/oauth/jwks",
		"scopes_supported":                      []string{scope},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (s *Service) register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid registration JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
		return
	}
	for _, uri := range req.RedirectURIs {
		if !validRedirectURI(uri) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URIs must be https or http loopback")
			return
		}
	}
	clientID, err := s.sign(signedPayload{Type: "client", RedirectURIs: req.RedirectURIs, Scope: scope, Nonce: nonce(), Iat: s.now().Unix()})
	if err != nil {
		http.Error(w, "could not register client", http.StatusInternalServerError)
		return
	}
	s.logger.InfoContext(r.Context(), "client registered", "client_name", req.ClientName, "redirect_uris", len(req.RedirectURIs))
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        s.now().Unix(),
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      scope,
	})
}

type authorizeData struct {
	Fields url.Values
	Error  string
}

func (s *Service) authorizePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if err := s.validateClientRedirect(q.Get("client_id"), q.Get("redirect_uri")); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	renderAuthorize(w, http.StatusOK, authorizeData{Fields: q})
}

func renderAuthorize(w http.ResponseWriter, status int, data authorizeData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_ = authorizeTemplate.Execute(w, data)
}

func (s *Service) authorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	clientID, redirectURI := f.Get("client_id"), f.Get("redirect_uri")
	if err := s.validateClientRedirect(clientID, redirectURI); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.CheckSecret(f.Get("secret_token")) {
		s.logger.WarnContext(r.Context(), "authorization rejected", "reason", "invalid_secret")
		renderAuthorize(w, http.StatusUnauthorized, authorizeData{Fields: f, Error: "That secret token is not valid."})
		return
	}
	clientName, ok := ValidateClientName(f.Get("client_name"))
	if !ok {
		renderAuthorize(w, http.StatusBadRequest, authorizeData{Fields: f, Error: "Client name is required (letters, digits, '.', '_', '-', spaces)."})
		return
	}
	if f.Get("response_type") != "code" {
		oauthError(w, http.StatusBadRequest, "unsupported_response_type", "response_type must be code")
		return
	}
	challenge := f.Get("code_challenge")
	if f.Get("code_challenge_method") != "S256" || len(challenge) < 43 || len(challenge) > 128 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "S256 PKCE is required")
		return
	}
	code, err := s.sign(signedPayload{
		Type: "code", ClientID: clientID, ClientName: clientName, RedirectURI: redirectURI,
		Challenge: challenge, Scope: scope, Nonce: nonce(),
		Exp: s.now().Add(codeTTL).Unix(), Iat: s.now().Unix(),
	})
	if err != nil {
		http.Error(w, "could not authorize", http.StatusInternalServerError)
		return
	}
	target, _ := url.Parse(redirectURI)
	q := target.Query()
	q.Set("code", code)
	if state := f.Get("state"); state != "" {
		q.Set("state", state)
	}
	target.RawQuery = q.Encode()
	s.logger.InfoContext(r.Context(), "authorization code issued", "client", clientName, "redirect_host", target.Host)
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.tokenFromCode(w, r)
	case "refresh_token":
		s.tokenFromRefresh(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Service) tokenFromCode(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	raw := f.Get("code")
	var code signedPayload
	if err := s.verify(raw, "code", &code); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	if s.now().Unix() > code.Exp {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
		return
	}
	if code.ClientID != f.Get("client_id") || code.RedirectURI != f.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "client_id or redirect_uri mismatch")
		return
	}
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(code.Challenge)) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if !s.consume(raw, code.Exp) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code already used")
		return
	}
	s.writeTokens(w, r, code.ClientID, code.ClientName)
}

func (s *Service) tokenFromRefresh(w http.ResponseWriter, r *http.Request) {
	var refresh signedPayload
	if err := s.verify(r.PostForm.Get("refresh_token"), "refresh", &refresh); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}
	if s.now().Unix() > refresh.Exp {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	if id := r.PostForm.Get("client_id"); id != "" && id != refresh.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	s.writeTokens(w, r, refresh.ClientID, refresh.ClientName)
}

func (s *Service) writeTokens(w http.ResponseWriter, r *http.Request, clientID, clientName string) {
	now := s.now()
	access, err1 := s.sign(signedPayload{Type: "access", ClientID: clientID, ClientName: clientName, Scope: scope, Nonce: nonce(), Exp: now.Add(accessTTL).Unix(), Iat: now.Unix()})
	refresh, err2 := s.sign(signedPayload{Type: "refresh", ClientID: clientID, ClientName: clientName, Scope: scope, Nonce: nonce(), Exp: now.Add(refreshTTL).Unix(), Iat: now.Unix()})
	if err := errors.Join(err1, err2); err != nil {
		http.Error(w, "could not issue tokens", http.StatusInternalServerError)
		return
	}
	s.logger.InfoContext(r.Context(), "tokens issued", "client", clientName)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
		"scope":         scope,
	})
}

// RequireBearer protects the MCP endpoint with OAuth access tokens.
func (s *Service) RequireBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r)
		var claims signedPayload
		if ok {
			if err := s.verify(token, "access", &claims); err != nil || s.now().Unix() > claims.Exp {
				ok = false
			}
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q, scope=%q`, s.baseURL+"/.well-known/oauth-protected-resource", scope))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithClientName(r.Context(), claims.ClientName)))
	})
}

// RequireStaticBearer protects the HTTP API for scripts and CLIs, which send
// "Authorization: Bearer <client_name>:<secret>". The client name is required
// and is logged with every request so callers can be told apart.
func (s *Service) RequireStaticBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credential, ok := bearer(r)
		name, token, found := strings.Cut(credential, ":")
		if ok && found {
			if clean, valid := ValidateClientName(name); valid && s.CheckSecret(token) {
				next.ServeHTTP(w, r.WithContext(WithClientName(r.Context(), clean)))
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="file-share", error="invalid_token"`)
		http.Error(w, `unauthorized: send "Authorization: Bearer <client_name>:<secret>"`, http.StatusUnauthorized)
	})
}

// UploadGrant authorizes one HTTP upload without the secret, so an agent can
// hand a short-lived URL to curl. FileID set means "replace this file".
type UploadGrant struct {
	Namespace  string
	Filename   string
	FileID     string
	ClientName string
}

func (s *Service) SignUpload(g UploadGrant, ttl time.Duration) string {
	token, _ := s.sign(signedPayload{Type: "upload", Namespace: g.Namespace, Filename: g.Filename, FileID: g.FileID, ClientName: g.ClientName, Nonce: nonce(), Exp: s.now().Add(ttl).Unix(), Iat: s.now().Unix()})
	return token
}

func (s *Service) VerifyUpload(token string) (UploadGrant, error) {
	var p signedPayload
	if err := s.verify(token, "upload", &p); err != nil {
		return UploadGrant{}, err
	}
	if s.now().Unix() > p.Exp {
		return UploadGrant{}, errors.New("upload URL expired")
	}
	return UploadGrant{Namespace: p.Namespace, Filename: p.Filename, FileID: p.FileID, ClientName: p.ClientName}, nil
}

// DownloadGrant lets the holder fetch one version (0 = current) of a file,
// bypassing its password and working even while it is deleted, so agents can
// hand out or recover exact bytes.
type DownloadGrant struct {
	FileID  string
	Version int
}

func (s *Service) SignDownload(g DownloadGrant, ttl time.Duration) string {
	token, _ := s.sign(signedPayload{Type: "download", FileID: g.FileID, Version: g.Version, Nonce: nonce(), Exp: s.now().Add(ttl).Unix(), Iat: s.now().Unix()})
	return token
}

func (s *Service) VerifyDownload(token string) (DownloadGrant, error) {
	var p signedPayload
	if err := s.verify(token, "download", &p); err != nil {
		return DownloadGrant{}, err
	}
	if s.now().Unix() > p.Exp {
		return DownloadGrant{}, errors.New("download URL expired")
	}
	return DownloadGrant{FileID: p.FileID, Version: p.Version}, nil
}

// MAC returns an HMAC of parts under the secret, for callers that need their
// own unforgeable values (for example password cookies).
func (s *Service) MAC(parts ...string) string {
	mac := hmac.New(sha256.New, s.secret)
	for _, p := range parts {
		mac.Write([]byte(p))
		mac.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func bearer(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if len(header) < 7 || !strings.EqualFold(header[:7], "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(header[7:])
	return token, token != ""
}

func (s *Service) validateClientRedirect(clientID, redirectURI string) error {
	var client signedPayload
	if err := s.verify(clientID, "client", &client); err != nil {
		return errors.New("unknown client_id")
	}
	for _, registered := range client.RedirectURIs {
		if redirectURIsMatch(registered, redirectURI) {
			return nil
		}
	}
	return errors.New("redirect_uri was not registered")
}

// redirectURIsMatch is exact, except loopback http URIs may change port
// (RFC 8252 §7.3) so native clients can bind an ephemeral port per flow.
func redirectURIsMatch(registered, presented string) bool {
	if registered == presented {
		return true
	}
	reg, err1 := url.Parse(registered)
	pre, err2 := url.Parse(presented)
	if err1 != nil || err2 != nil || !isLoopback(reg) || !isLoopback(pre) {
		return false
	}
	return strings.EqualFold(reg.Hostname(), pre.Hostname()) && reg.Path == pre.Path
}

func isLoopback(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

func validRedirectURI(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || isLoopback(u)
}

// ValidateClientName trims and checks a caller-chosen client label.
func ValidateClientName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxClientName {
		return "", false
	}
	for _, r := range name {
		ok := r == ' ' || r == '.' || r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !ok {
			return "", false
		}
	}
	return name, true
}

func (s *Service) sign(p signedPayload) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Service) verify(token, wantType string, p *signedPayload) error {
	if len(s.secret) == 0 {
		return errors.New("no secret configured")
	}
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return errors.New("malformed token")
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return errors.New("malformed signature")
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(body))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("bad signature")
	}
	data, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, p); err != nil {
		return err
	}
	if p.Type != wantType {
		return errors.New("wrong token type")
	}
	return nil
}

func (s *Service) consume(code string, exp int64) bool {
	sum := sha256.Sum256([]byte(code))
	key := string(sum[:])
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.consumed {
		if now > e {
			delete(s.consumed, k)
		}
	}
	if _, used := s.consumed[key]; used {
		return false
	}
	s.consumed[key] = exp
	return true
}

func nonce() string { return rand.Text() }

type clientNameKey struct{}

func WithClientName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, clientNameKey{}, name)
}

// ClientName returns the authenticated client's label, or "" if none.
func ClientName(ctx context.Context) string {
	name, _ := ctx.Value(clientNameKey{}).(string)
	return name
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

var authorizeTemplate = template.Must(template.New("authorize").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize file-share</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:34rem;margin:12vh auto;padding:0 1rem;color:#172026}input{display:block;width:100%;box-sizing:border-box;margin:.4rem 0 1rem;padding:.7rem;font:inherit;border:1px solid #b8c1cc;border-radius:6px}button{padding:.7rem 1rem;font:inherit;border:0;border-radius:6px;background:#172026;color:#fff;cursor:pointer}.error{color:#a00}.hint{font-size:.9rem;color:#5a6b78}</style></head>
<body><h1>Authorize file-share</h1>
<p>This gives the connecting app full control of your files: upload, replace, delete, restore and set passwords.</p>
{{with .Error}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/oauth/authorize">
{{range $key, $values := .Fields}}{{if and (ne $key "client_name") (ne $key "secret_token")}}{{range $values}}<input type="hidden" name="{{$key}}" value="{{.}}">{{end}}{{end}}{{end}}
<label for="client_name">Client name</label><input id="client_name" name="client_name" type="text" autocomplete="off" autofocus required maxlength="64" placeholder="e.g. claude, codex">
<label for="secret_token">Secret token</label><input id="secret_token" name="secret_token" type="password" required autocomplete="current-password">
<p class="hint">The client name is logged with every request so you can tell connectors apart.</p>
<button type="submit">Authorize</button></form></body></html>`))
