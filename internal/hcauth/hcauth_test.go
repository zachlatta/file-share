package hcauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeHCA imitates the token and userinfo endpoints of Hack Club Auth.
func fakeHCA(t *testing.T, userinfo map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f := r.PostForm
		if f.Get("grant_type") != "authorization_code" || f.Get("code") != "good-code" ||
			f.Get("client_id") != "cid" || f.Get("client_secret") != "csecret" ||
			f.Get("redirect_uri") != "https://files.example.com/oauth/callback" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "idntk.abc", "token_type": "Bearer"})
	})
	mux.HandleFunc("GET /oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer idntk.abc" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(userinfo)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newClient(base string) *Client {
	return New(Config{ClientID: "cid", ClientSecret: "csecret", BaseURL: base, RedirectURL: "https://files.example.com/oauth/callback"})
}

func TestAuthorizeURL(t *testing.T) {
	c := New(Config{ClientID: "cid", ClientSecret: "csecret", RedirectURL: "https://files.example.com/oauth/callback"})
	u, err := url.Parse(c.AuthorizeURL("st8", false))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != "https://auth.hackclub.com/oauth/authorize" || q.Get("client_id") != "cid" ||
		q.Get("redirect_uri") != "https://files.example.com/oauth/callback" || q.Get("response_type") != "code" ||
		q.Get("scope") != "openid email" || q.Get("state") != "st8" || q.Has("prompt") {
		t.Fatalf("authorize URL = %s", u)
	}
	if u, _ := url.Parse(c.AuthorizeURL("st8", true)); u.Query().Get("prompt") != "login" {
		t.Fatalf("switch account should force login: %s", u)
	}
}

func TestEmail(t *testing.T) {
	srv := fakeHCA(t, map[string]any{"sub": "ident!x", "email": " Zach@HackClub.com ", "email_verified": true})
	email, err := newClient(srv.URL).Email(t.Context(), "good-code")
	if err != nil || email != "zach@hackclub.com" {
		t.Fatalf("email = %q, %v", email, err)
	}
	if _, err := newClient(srv.URL).Email(t.Context(), "bad-code"); err == nil {
		t.Fatal("a rejected code must fail")
	}
}

func TestEmailRequiresVerifiedEmail(t *testing.T) {
	for _, info := range []map[string]any{
		{"sub": "ident!x", "email": "zach@hackclub.com", "email_verified": false},
		{"sub": "ident!x", "email": "zach@hackclub.com"},
		{"sub": "ident!x", "email_verified": true},
	} {
		srv := fakeHCA(t, info)
		if email, err := newClient(srv.URL).Email(t.Context(), "good-code"); err == nil || !strings.Contains(err.Error(), "email") {
			t.Errorf("%v: email = %q, err = %v", info, email, err)
		}
	}
}
