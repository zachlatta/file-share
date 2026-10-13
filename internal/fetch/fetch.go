// Package fetch downloads a URL for "upload from URL", refusing to connect
// to private, loopback, link-local or tailnet (CGNAT) addresses so a public
// file can never be minted from something only this server can reach.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"syscall"
	"time"
)

type Options struct {
	// AllowPrivate disables the address guard (tests only).
	AllowPrivate bool
}

type Fetcher struct{ client *http.Client }

type Result struct {
	Body          io.ReadCloser
	Filename      string
	ContentType   string
	ContentLength int64
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func blocked(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() || addr.IsInterfaceLocalMulticast() || cgnat.Contains(addr)
}

func New(opts Options) *Fetcher {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !opts.AllowPrivate {
		// Checked at connect time, after DNS resolution, so rebinding and
		// redirects to private hosts are caught too.
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(host)
			if err != nil || blocked(addr) {
				return fmt.Errorf("fetching from %s is not allowed", host)
			}
			return nil
		}
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Fetcher{client: &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return errors.New("redirect to a non-HTTP URL")
			}
			return nil
		},
	}}
}

// Get starts downloading raw. The caller must close Result.Body.
func (f *Fetcher) Get(ctx context.Context, raw string) (*Result, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("source_url must be an http(s) URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "file-share/1 (+https://github.com/zachlatta/file-share)")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u.Redacted(), err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		resp.Body.Close()
		return nil, fmt.Errorf("fetch %s: HTTP %d", u.Redacted(), resp.StatusCode)
	}
	name := ""
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil {
		name = path.Base(params["filename"])
	}
	if name == "" || name == "." || name == "/" {
		name = path.Base(resp.Request.URL.Path)
	}
	if name == "" || name == "." || name == "/" {
		name = "download"
	}
	contentType := resp.Header.Get("Content-Type")
	return &Result{Body: resp.Body, Filename: name, ContentType: contentType, ContentLength: resp.ContentLength}, nil
}
