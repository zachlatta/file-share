package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zachlatta/file-share/internal/files"
)

func isMedia(contentType string) bool {
	return strings.HasPrefix(contentType, "audio/") || strings.HasPrefix(contentType, "video/")
}

// countingWriter records the status and how many body bytes went out.
type countingWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (c *countingWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// logRequest adds a served file to the request log. Like the audit log, it
// keeps no query string and strips the referrer's.
func (h *Handler) logRequest(r *http.Request, f files.File, w *countingWriter, took time.Duration) {
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	if status == http.StatusNotFound || status >= 500 {
		return
	}
	req := files.FileRequest{
		FileID: f.ID, Namespace: f.Namespace, Name: f.Name, Version: f.Version, Method: r.Method, Status: status,
		BytesSent: w.n, Size: f.Size, IP: clientIP(r, h.ipHeader), UserAgent: r.UserAgent(), Referer: stripQuery(r.Referer()),
		DurationMS: int(took.Milliseconds()),
	}
	if h.ipHeader != "" {
		req.Country = r.Header.Get("CF-IPCountry")
	}
	if cr := w.Header().Get("Content-Range"); status == http.StatusPartialContent && cr != "" {
		// "bytes <start>-<end>/<size>"
		first, _, _ := strings.Cut(strings.TrimPrefix(cr, "bytes "), "-")
		req.RangeStart, _ = strconv.ParseInt(first, 10, 64)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
	defer cancel()
	if err := h.files.RecordRequest(ctx, req); err != nil {
		h.logger.Warn("request log write failed", "error", err)
	}
}
