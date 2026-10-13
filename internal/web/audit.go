package web

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zachlatta/file-share/internal/files"
)

// audit records an access to a restricted file. Failures are logged and
// never block serving. Query strings are never recorded: they can carry
// passwords and tokens.
func (h *Handler) audit(r *http.Request, f files.File, event, via, email string, status, version int) {
	e := files.AccessEvent{
		FileID: f.ID, Namespace: f.Namespace, Name: f.Name, Version: version,
		Event: event, Via: via, Email: email, Status: status,
		IP: clientIP(r, h.ipHeader), UserAgent: r.UserAgent(), Referer: stripQuery(r.Referer()),
		RemoteAddr: socketIP(r), ForwardedFor: r.Header.Get("X-Forwarded-For"),
	}
	if h.ipHeader != "" {
		e.Country = r.Header.Get("CF-IPCountry") // set by Cloudflare alongside CF-Connecting-IP
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
	defer cancel()
	if err := h.files.RecordAccess(ctx, e); err != nil {
		h.logger.Warn("audit log write failed", "event", event, "error", err)
	}
}

// clientIP is the visitor's IP: from header when the deployment names a
// trusted proxy header and it holds a valid IP, else the socket address.
func clientIP(r *http.Request, header string) string {
	if header != "" {
		value, _, _ := strings.Cut(r.Header.Get(header), ",")
		if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
			return ip.String()
		}
	}
	return socketIP(r)
}

func socketIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func stripQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return ""
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return u.String()
}

// countsAsView skips HEAD requests and the follow-up chunks of a range
// request (video seeking), so one viewing is one entry.
func countsAsView(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	rng := r.Header.Get("Range")
	return rng == "" || strings.HasPrefix(strings.ReplaceAll(rng, " ", ""), "bytes=0-")
}
