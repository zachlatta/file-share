package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zachlatta/file-share/internal/blob"
	"github.com/zachlatta/file-share/internal/config"
	"github.com/zachlatta/file-share/internal/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

const secret = "end-to-end-secret-0123456789abcdef"

func start(t *testing.T) (*httptest.Server, *App) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	server.Start()
	t.Cleanup(server.Close)
	cfg := config.Config{
		Secret: secret, PublicURL: server.URL, DatabaseURL: pgtest.New(t),
		Retention: 30 * 24 * time.Hour, MaxUploadBytes: 10 << 20, PurgeInterval: time.Hour, Version: "test",
	}
	app, err := New(context.Background(), cfg, Options{Blobs: blob.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	server.Config.Handler = app.Handler()
	return server, app
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// oauth performs dynamic registration, the secret-token authorize step and
// the PKCE code exchange exactly as an MCP client would.
func oauth(t *testing.T, base string) string {
	t.Helper()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	redirect := "http://127.0.0.1:9999/callback"
	resp, err := http.Post(base+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"e2e","redirect_uris":["`+redirect+`"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	resp.Body.Close()
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	resp, err = noRedirect.PostForm(base+"/oauth/authorize", url.Values{
		"client_id": {reg.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"secret_token": {secret}, "client_name": {"e2e-test"},
	})
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %v %v", resp.StatusCode, err)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	resp, err = http.PostForm(base+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {reg.ClientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	if tok.AccessToken == "" {
		t.Fatal("no access token")
	}
	return tok.AccessToken
}

func TestEndToEnd(t *testing.T) {
	server, _ := start(t)

	// The MCP endpoint demands OAuth.
	resp, _ := http.Post(server.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatalf("anonymous mcp: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	token := oauth(t, server.URL)
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "test"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint: server.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token}},
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "upload_file", Arguments: map[string]any{"name": "hello.txt", "content_text": "hi from mcp"}})
	if err != nil || res.IsError {
		t.Fatalf("upload_file: %v %+v", err, res)
	}
	data, _ := json.Marshal(res.StructuredContent)
	var file struct{ ID, URL string }
	_ = json.Unmarshal(data, &file)
	if !strings.HasPrefix(file.URL, server.URL+"/") {
		t.Fatalf("url = %q", file.URL)
	}
	resp, err = http.Get(file.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hi from mcp" {
		t.Fatalf("public get: %d %q", resp.StatusCode, body)
	}

	// Large-file path: signed upload URL, then a plain HTTP PUT.
	res, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "create_upload_url", Arguments: map[string]any{"name": "big.bin"}})
	if err != nil || res.IsError {
		t.Fatalf("create_upload_url: %v %+v", err, res)
	}
	data, _ = json.Marshal(res.StructuredContent)
	var up struct {
		UploadURL string `json:"upload_url"`
	}
	_ = json.Unmarshal(data, &up)
	req, _ := http.NewRequest(http.MethodPut, up.UploadURL, strings.NewReader(strings.Repeat("z", 3<<20)))
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("signed PUT: %v %v", err, resp.StatusCode)
	}
	var created struct {
		URL  string `json:"url"`
		Size int64  `json:"size"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.Size != 3<<20 {
		t.Fatalf("created = %+v", created)
	}

	// Static bearer API.
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/api/files", nil)
	req.Header.Set("Authorization", "Bearer e2e:"+secret)
	resp, _ = http.DefaultClient.Do(req)
	var list struct{ Files []any }
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Files) != 2 {
		t.Fatalf("api list = %d", len(list.Files))
	}
}

func TestHackClubAuthWiring(t *testing.T) {
	server := httptest.NewServer(nil)
	t.Cleanup(server.Close)
	cfg := config.Config{
		Secret: secret, PublicURL: server.URL, DatabaseURL: pgtest.New(t),
		Retention: 30 * 24 * time.Hour, MaxUploadBytes: 10 << 20, PurgeInterval: time.Hour, Version: "test",
		HCAClientID: "cid", HCAClientSecret: "csecret", HCAURL: "https://auth.hackclub.com",
		AdminToken: "app-admin-token-0123456789abcdef",
	}
	app, err := New(context.Background(), cfg, Options{Blobs: blob.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	next := "/00000000-0000-4000-8000-000000000000/a.txt"
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/hackclub?next="+url.QueryEscape(next), nil))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Host != "auth.hackclub.com" || loc.Query().Get("client_id") != "cid" ||
		loc.Query().Get("redirect_uri") != server.URL+"/oauth/callback" {
		t.Fatalf("login start: %d %s", rec.Code, loc)
	}
	if strings.Contains(loc.String(), "csecret") {
		t.Fatal("client secret leaked into the authorize URL")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/files", nil)
	req.Header.Set("Authorization", "Bearer app-admin-token-0123456789abcdef")
	rec = httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin API: %d %s", rec.Code, rec.Body)
	}
}

// A script can call any MCP tool with one curl: the static bearer and a
// single JSON-RPC tools/call, no OAuth and no initialize handshake.
func TestMCPToolCallWithStaticBearer(t *testing.T) {
	server, _ := start(t)
	call := func(authz, body string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", authz)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"upload_file","arguments":{"name":"s.txt","content_text":"scripted"}}}`
	status, out := call("Bearer script:"+secret, body)
	if status != http.StatusOK || !strings.Contains(out, `"structuredContent"`) || !strings.Contains(out, `s.txt`) {
		t.Fatalf("tools/call: %d %s", status, out)
	}
	if status, _ := call("Bearer script:wrong", body); status != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", status)
	}
}
