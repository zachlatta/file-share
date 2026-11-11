package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zachlatta/file-share/internal/files"
)

const sampleMarkdown = "# Trip notes\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n- [x] packed\n- [ ] booked\n\n" +
	"```go\nfmt.Println(\"<hi>\")\n```\n\n![map](map.png)\n\n[docs](other.md) [bad](javascript:alert(1)) [web](https://example.com)\n\n" +
	"<script>alert('x')</script>\n\n<img src=x onerror=alert(1)>\n"

// browser is a top-level navigation the way Chrome, Firefox and Safari send it.
func browser(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	return req
}

func (e *env) uploadTyped(t *testing.T, name, contentType, body string) files.File {
	t.Helper()
	f, err := e.files.Upload(context.Background(), files.UploadInput{Name: name, ContentType: contentType, Body: strings.NewReader(body), Size: -1})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMarkdownRawForNonBrowsers(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "notes.md", sampleMarkdown, "")
	cases := map[string]func(*http.Request){
		"curl":  func(r *http.Request) { r.Header.Set("Accept", "*/*"); r.Header.Set("User-Agent", "curl/8.5.0") },
		"bare":  func(*http.Request) {},
		"wget":  func(r *http.Request) { r.Header.Set("Accept", "*/*"); r.Header.Set("User-Agent", "Wget/1.21") },
		"fetch": func(r *http.Request) { r.Header.Set("Accept", "*/*"); r.Header.Set("Sec-Fetch-Dest", "empty") },
		// A browser asking for the file from a script or iframe gets the
		// file, not a page.
		"iframe": func(r *http.Request) { r.Header.Set("Accept", "text/html"); r.Header.Set("Sec-Fetch-Dest", "iframe") },
		"markdown-accept": func(r *http.Request) {
			r.Header.Set("Accept", "text/markdown, text/plain;q=0.9, */*;q=0.1")
		},
	}
	for name, set := range cases {
		req := httptest.NewRequest(http.MethodGet, urlPath(f), nil)
		set(req)
		rec := e.do(req)
		if rec.Code != 200 || rec.Body.String() != sampleMarkdown {
			t.Fatalf("%s: %d %q", name, rec.Code, rec.Body)
		}
		h := rec.Header()
		if h.Get("Content-Type") != "text/markdown; charset=utf-8" || h.Get("ETag") != `"`+f.SHA256+`"` || !strings.HasPrefix(h.Get("Content-Disposition"), "inline") {
			t.Fatalf("%s headers: %v", name, h)
		}
		if !strings.Contains(h.Get("Vary"), "Accept") || !strings.Contains(h.Get("Vary"), "Sec-Fetch-Dest") {
			t.Fatalf("%s vary: %q", name, h.Get("Vary"))
		}
		// Cloudflare ignores Vary, so neither form may sit in a shared cache.
		if h.Get("Cache-Control") != "private, no-cache" {
			t.Fatalf("%s cache-control: %q", name, h.Get("Cache-Control"))
		}
	}
}

func TestMarkdownRenderedForBrowsers(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "notes.md", sampleMarkdown, "")
	rec := e.do(browser(urlPath(f)))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	h := rec.Header()
	if h.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("content type %q", h.Get("Content-Type"))
	}
	if v := h.Get("Vary"); !strings.Contains(v, "Accept") || !strings.Contains(v, "Sec-Fetch-Dest") {
		t.Fatalf("vary %q", v)
	}
	// The page and the file must never share a cache entry or validator.
	if h.Get("ETag") == `"`+f.SHA256+`"` || !strings.Contains(h.Get("Cache-Control"), "private") {
		t.Fatalf("cache headers: %v", h)
	}
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("csp %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("csp allows unsafe-inline: %q", csp)
	}
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers: %v", h)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<h1", "Trip notes</h1>", "<table>", "<td>1</td>", `type="checkbox"`, "checked",
		`<code class="language-go">`, "fmt.Println(&#34;&lt;hi&gt;&#34;)",
		`<img src="map.png" alt="map"`, `href="other.md"`, `href="https://example.com"`,
		"notes.md", "?raw=1", "?download=1", "Raw", "Download",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, bad := range []string{"<script", "javascript:", "onerror", "alert("} {
		if strings.Contains(strings.ToLower(body), bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	// HEAD matches GET without a body.
	head := browser(urlPath(f))
	head.Method = http.MethodHead
	if rec := e.do(head); rec.Code != 200 || rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("head: %d %q %v", rec.Code, rec.Body, rec.Header())
	}
}

func TestMarkdownBrowserWithoutFetchMetadata(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "notes.md", sampleMarkdown, "")
	req := httptest.NewRequest(http.MethodGet, urlPath(f), nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	if rec := e.do(req); rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("older browser got %q", rec.Header().Get("Content-Type"))
	}
}

func TestMarkdownRawAndDownloadLinks(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "notes.md", sampleMarkdown, "")
	rec := e.do(browser(urlPath(f) + "?raw=1"))
	if rec.Body.String() != sampleMarkdown || rec.Header().Get("Content-Type") != "text/markdown; charset=utf-8" ||
		!strings.HasPrefix(rec.Header().Get("Content-Disposition"), "inline") {
		t.Fatalf("raw: %v %q", rec.Header(), rec.Body)
	}
	rec = e.do(browser(urlPath(f) + "?download=1"))
	if rec.Body.String() != sampleMarkdown || !strings.HasPrefix(rec.Header().Get("Content-Disposition"), `attachment; filename=notes.md`) {
		t.Fatalf("download: %v %q", rec.Header(), rec.Body)
	}
	// A browser range request (resuming, seeking) gets bytes.
	req := browser(urlPath(f))
	req.Header.Set("Range", "bytes=2-6")
	if rec := e.do(req); rec.Code != http.StatusPartialContent || rec.Body.String() != sampleMarkdown[2:7] {
		t.Fatalf("range: %d %q", rec.Code, rec.Body)
	}
}

func TestMarkdownDetection(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name, contentType string
		render            bool
	}{
		{"a.md", "", true},
		{"b.markdown", "", true},
		{"c.MD", "", true},
		// Agents upload Markdown as text/plain so it opens inline.
		{"d.md", "text/plain; charset=utf-8", true},
		{"e.txt", "text/markdown", true},
		{"f.txt", "", false},
		{"g.md", "text/html; charset=utf-8", false},
		{"h.md", "application/octet-stream", true}, // detected from the name
		{"i.html", "", false},
	}
	for _, c := range cases {
		f := e.uploadTyped(t, c.name, c.contentType, "# hi\n")
		rec := e.do(browser(urlPath(f)))
		got := rec.Header().Get("Content-Type") == "text/html; charset=utf-8" && strings.Contains(rec.Body.String(), "<h1")
		if c.name == "i.html" {
			got = rec.Body.String() != "# hi\n"
		}
		if got != c.render {
			t.Errorf("%s (%q): rendered=%v, want %v (%q)", c.name, c.contentType, got, c.render, rec.Header().Get("Content-Type"))
		}
	}
}

func TestMarkdownTooLargeIsServedRaw(t *testing.T) {
	e := newEnv(t)
	big := "# big\n" + strings.Repeat("x", maxRenderBytes)
	f := e.upload(t, "big.md", big, "")
	rec := e.do(browser(urlPath(f)))
	if rec.Body.Len() != len(big) || rec.Header().Get("Content-Type") != "text/markdown; charset=utf-8" {
		t.Fatalf("big: %q %d", rec.Header().Get("Content-Type"), rec.Body.Len())
	}
}

func TestMarkdownRenderedViewKeepsAccessChecks(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "secret.md", "# classified\n", "hunter22")
	// No credentials: the gate, not the document.
	rec := e.do(browser(urlPath(f)))
	if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "classified") {
		t.Fatalf("anonymous: %d %q", rec.Code, rec.Body)
	}
	// Basic auth opens the rendered page and records one view.
	req := browser(urlPath(f))
	req.SetBasicAuth("", "hunter22")
	rec = e.do(req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "classified</h1>") {
		t.Fatalf("authorized: %d %q", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("restricted page cacheable: %q", rec.Header().Get("Cache-Control"))
	}
	var views int
	for _, ev := range e.events(t) {
		if ev.Event == "view" && ev.Via == "basic_auth" && ev.FileID == f.ID {
			views++
		}
	}
	if views != 1 {
		t.Fatalf("views logged: %d", views)
	}
}

func TestNonMarkdownUnchangedForBrowsers(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "hello.txt", "hello", "")
	rec := e.do(browser(urlPath(f)))
	if rec.Body.String() != "hello" || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("txt: %v %q", rec.Header(), rec.Body)
	}
	if rec.Header().Get("Vary") != "" {
		t.Fatalf("txt vary: %q", rec.Header().Get("Vary"))
	}
}

// The page's only style block must match the hash the CSP allows, or the
// browser drops the styling.
func TestMarkdownPageStyleMatchesCSP(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "notes.md", "# hi\n", "")
	rec := e.do(browser(urlPath(f)))
	body := rec.Body.String()
	_, rest, _ := strings.Cut(body, "<style>")
	css, _, ok := strings.Cut(rest, "</style>")
	if !ok || strings.Count(body, "<style") != 1 {
		t.Fatalf("style block: %q", body)
	}
	sum := sha256.Sum256([]byte(css))
	want := "style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, want) {
		t.Fatalf("csp %q lacks %q", csp, want)
	}
}

func TestMarkdownHonorsStoredCharset(t *testing.T) {
	e := newEnv(t)
	latin := e.uploadTyped(t, "latin.md", "text/plain; charset=iso-8859-1", "# Caf\xe9\n")
	rec := e.do(browser(urlPath(latin)))
	if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(rec.Body.String(), "Café</h1>") {
		t.Fatalf("latin-1: %q %q", rec.Header().Get("Content-Type"), rec.Body)
	}
	win := e.uploadTyped(t, "win.md", "text/markdown; charset=windows-1252", "# \x93quoted\x94\n")
	if rec := e.do(browser(urlPath(win))); !strings.Contains(rec.Body.String(), "“quoted”</h1>") {
		t.Fatalf("windows-1252: %q", rec.Body)
	}
	// Bytes that are not valid in the declared (or default UTF-8) charset,
	// or a charset we cannot decode, are served raw rather than garbled.
	for _, c := range []struct{ name, contentType, body string }{
		{"bad.md", "text/markdown", "# Caf\xe9\n"},
		{"bad8.md", "text/plain; charset=utf-8", "# Caf\xe9\n"},
		{"odd.md", "text/markdown; charset=x-no-such-charset", "# hi\n"},
	} {
		f := e.uploadTyped(t, c.name, c.contentType, c.body)
		rec := e.do(browser(urlPath(f)))
		if rec.Body.String() != c.body || rec.Header().Get("Content-Type") != c.contentType {
			t.Errorf("%s: %q %q", c.name, rec.Header().Get("Content-Type"), rec.Body)
		}
	}
}

func TestMarkdownLinksKeepQueryPassword(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "secret.md", "# classified\n", "p&ss word")
	rec := e.do(browser(urlPath(f) + "?password=p%26ss+word"))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "classified</h1>") {
		t.Fatalf("page: %d %q", rec.Code, body)
	}
	for _, link := range []string{`href="?password=p%26ss&#43;word&amp;raw=1"`, `href="?password=p%26ss&#43;word&amp;download=1"`} {
		if !strings.Contains(body, link) {
			t.Fatalf("page lacks %s: %q", link, body)
		}
	}
	for _, q := range []string{"?password=p%26ss+word&raw=1", "?password=p%26ss+word&download=1"} {
		if rec := e.do(browser(urlPath(f) + q)); rec.Code != 200 || rec.Body.String() != "# classified\n" {
			t.Fatalf("%s: %d %q", q, rec.Code, rec.Body)
		}
	}
	// Other ways in never put a password into the page.
	req := browser(urlPath(f))
	req.SetBasicAuth("", "p&ss word")
	if body := e.do(req).Body.String(); strings.Contains(body, "password=") || !strings.Contains(body, `href="?raw=1"`) {
		t.Fatalf("basic auth page: %q", body)
	}
	// A wrong query password still gets the gate.
	if rec := e.do(browser(urlPath(f) + "?password=nope&raw=1")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", rec.Code)
	}
}

// Without fetch metadata, Accept decides: HTML only when the client prefers
// it strictly over Markdown, plain text and the stored type.
func TestMarkdownAcceptNegotiation(t *testing.T) {
	e := newEnv(t)
	f := e.upload(t, "notes.md", "# hi\n", "")
	cases := map[string]bool{
		"text/html, */*;q=0.8": true,
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8": true,
		"text/html":                            true,
		"text/html;q=0.9, text/*;q=0.5":        true,
		"*/*":                                  false,
		"text/*":                               false,
		"text/html, text/*":                    false,
		"text/markdown, text/html;q=0.5":       false,
		"text/markdown;q=1.0, text/html;q=0.5": false,
		"text/html;q=0.5, text/plain;q=0.5":    false,
		"text/html;q=0":                        false,
		"application/json":                     false,
		"":                                     false,
	}
	for accept, page := range cases {
		req := httptest.NewRequest(http.MethodGet, urlPath(f), nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		got := e.do(req).Header().Get("Content-Type") == "text/html; charset=utf-8"
		if got != page {
			t.Errorf("Accept %q: page=%v, want %v", accept, got, page)
		}
	}
}

func TestMarkdownTableAlignmentAndLooseTaskLists(t *testing.T) {
	html, err := renderMarkdown([]byte("| l | c | r |\n|:--|:-:|--:|\n| 1 | 2 | 3 |\n\n- [x] one\n\n- [ ] two\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`<th align="left">`, `<td align="center">`, `<td align="right">`, `type="checkbox"`} {
		if !strings.Contains(string(html), want) {
			t.Errorf("rendered lacks %q: %s", want, html)
		}
	}
	if !strings.Contains(markdownCSS, "li:has(>p>input[type=checkbox])") {
		t.Errorf("loose task list items keep their bullets")
	}
}
