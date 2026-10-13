// Package hcauth signs visitors in with Hack Club Auth (auth.hackclub.com),
// an OpenID Connect provider, to learn their verified email address.
//
// The server is a confidential client: it exchanges the authorization code
// with its client secret over a direct HTTPS call, then reads the email from
// the userinfo endpoint with the resulting access token. Nothing is stored;
// the caller turns the email into its own signed session.
package hcauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultBaseURL = "https://auth.hackclub.com"

type Config struct {
	ClientID     string
	ClientSecret string
	// BaseURL is the provider origin. Default: https://auth.hackclub.com.
	BaseURL string
	// RedirectURL is this server's registered callback, e.g.
	// https://files.zachlatta.com/oauth/callback.
	RedirectURL string
	HTTPClient  *http.Client
}

type Client struct {
	cfg  Config
	http *http.Client
}

func New(cfg Config) *Client {
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{cfg: cfg, http: client}
}

// AuthorizeURL is where to send the visitor to sign in. forceLogin asks the
// provider to re-authenticate, so the visitor can switch accounts.
func (c *Client) AuthorizeURL(state string, forceLogin bool) string {
	q := url.Values{
		"client_id":     {c.cfg.ClientID},
		"redirect_uri":  {c.cfg.RedirectURL},
		"response_type": {"code"},
		"scope":         {"openid email"},
		"state":         {state},
	}
	if forceLogin {
		q.Set("prompt", "login")
	}
	return c.cfg.BaseURL + "/oauth/authorize?" + q.Encode()
}

// Email exchanges an authorization code and returns the visitor's verified
// email address, trimmed and lowercased.
func (c *Client) Email(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURL},
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.do(req, "token exchange", &token); err != nil {
		return "", err
	}
	if token.AccessToken == "" {
		return "", errors.New("hack club auth: token response has no access_token")
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/oauth/userinfo", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	var info struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := c.do(req, "userinfo", &info); err != nil {
		return "", err
	}
	email := strings.ToLower(strings.TrimSpace(info.Email))
	if email == "" {
		return "", errors.New("hack club auth: account returned no email")
	}
	if !info.EmailVerified {
		return "", errors.New("hack club auth: email is not verified")
	}
	return email, nil
}

func (c *Client) do(req *http.Request, what string, into any) error {
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("hack club auth %s: %w", what, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("hack club auth %s: %w", what, err)
	}
	if res.StatusCode != http.StatusOK {
		// The body may echo request details, so only the status is reported.
		return fmt.Errorf("hack club auth %s: HTTP %d", what, res.StatusCode)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("hack club auth %s: invalid JSON: %w", what, err)
	}
	return nil
}
