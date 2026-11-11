package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"golang.org/x/text/encoding/htmlindex"

	"github.com/zachlatta/file-share/internal/files"
)

// Markdown files open as a rendered page in a browser, like a GitHub Gist,
// and as the exact stored bytes everywhere else (curl, wget, scripts,
// fetch()). ?raw=1 and ?download=1 always give the bytes.

// maxRenderBytes is the largest Markdown file rendered; bigger ones are
// served raw.
const maxRenderBytes = 512 << 10

// markdownVary names the request headers that choose between the page and
// the bytes.
const markdownVary = "Accept, Sec-Fetch-Dest"

var markdownExtensions = map[string]bool{".md": true, ".markdown": true}

// isMarkdown reports whether a stored file is Markdown: stored as
// text/markdown, or stored as plain text with a Markdown name (agents upload
// Markdown as text/plain so that it opens inline).
func isMarkdown(f files.File) bool {
	mediaType, _, _ := mime.ParseMediaType(f.ContentType)
	switch mediaType {
	case "text/markdown", "text/x-markdown":
		return true
	case "text/plain":
		return markdownExtensions[strings.ToLower(path.Ext(f.Name))]
	}
	return false
}

// wantsPage reports whether the request is a browser opening f as a page.
// Browsers send Sec-Fetch-Dest: document for a top-level navigation;
// fetch(), images and iframes send something else. Clients without fetch
// metadata get the page only if Accept prefers text/html to the file's own
// types, which curl, wget and HTTP libraries do not do by default.
func wantsPage(r *http.Request, f files.File) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	q := r.URL.Query()
	if q.Has("raw") || q.Has("download") || r.Header.Get("Range") != "" {
		return false
	}
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		return dest == "document"
	}
	return prefersHTML(r.Header.Get("Accept"), f.ContentType)
}

// prefersHTML reports whether accept gives text/html a strictly higher
// quality than text/markdown, text/plain and the stored type.
func prefersHTML(accept, stored string) bool {
	storedType, _, _ := mime.ParseMediaType(stored)
	html := acceptQuality(accept, "text/html")
	for _, other := range []string{"text/markdown", "text/plain", storedType} {
		if other != "" && acceptQuality(accept, other) >= html {
			return false
		}
	}
	return true
}

// acceptQuality is the q value accept gives mediaType, from its most specific
// matching range (type/subtype, then type/*, then */*), or 0.
func acceptQuality(accept, mediaType string) float64 {
	major, _, _ := strings.Cut(mediaType, "/")
	best, quality := -1, 0.0
	for _, part := range strings.Split(accept, ",") {
		rng, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		specificity := -1
		switch rng {
		case mediaType:
			specificity = 2
		case major + "/*":
			specificity = 1
		case "*/*":
			specificity = 0
		}
		if specificity <= best {
			continue
		}
		q := 1.0
		if v, err := strconv.ParseFloat(params["q"], 64); err == nil {
			q = v
		}
		best, quality = specificity, q
	}
	return quality
}

var markdown = goldmark.New(
	// Without html.WithUnsafe, goldmark drops raw HTML and dangerous link
	// schemes such as javascript:. The sanitizer below is a second line.
	goldmark.WithExtensions(
		// GitHub-flavored Markdown (extension.GFM), with table columns
		// aligned by the align attribute, since the sanitizer strips style.
		extension.Linkify, extension.Strikethrough, extension.TaskList,
		extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignAttribute)),
		extension.Footnote,
	),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
)

var markdownPolicy = func() *bluemonday.Policy {
	p := bluemonday.UGCPolicy()
	p.AllowAttrs("class").Matching(regexp.MustCompile(`^language-[\w+#.-]+$`)).OnElements("code")
	p.AllowAttrs("type").Matching(regexp.MustCompile(`^checkbox$`)).OnElements("input")
	p.AllowAttrs("checked", "disabled").OnElements("input")
	p.AllowAttrs("id").OnElements("h1", "h2", "h3", "h4", "h5", "h6", "li", "sup")
	p.AllowAttrs("align").Matching(regexp.MustCompile(`^(left|center|right)$`)).OnElements("th", "td")
	return p
}()

// renderMarkdown converts Markdown to sanitized HTML.
func renderMarkdown(src []byte) (template.HTML, error) {
	var buf bytes.Buffer
	if err := markdown.Convert(src, &buf); err != nil {
		return "", err
	}
	return template.HTML(markdownPolicy.SanitizeBytes(buf.Bytes())), nil
}

// decodeMarkdown converts src from the stored charset to UTF-8, the way a
// browser would read the raw file. It reports false if the charset is unknown
// or the bytes are not valid in it; such files are served raw, not garbled.
// No charset means UTF-8.
func decodeMarkdown(src []byte, contentType string) ([]byte, bool) {
	_, params, _ := mime.ParseMediaType(contentType)
	switch charset := strings.ToLower(strings.TrimSpace(params["charset"])); charset {
	case "", "utf-8", "utf8", "us-ascii":
		return src, utf8.Valid(src)
	default:
		enc, err := htmlindex.Get(charset)
		if err != nil {
			return nil, false
		}
		out, err := enc.NewDecoder().Bytes(src)
		if err != nil || !utf8.Valid(out) || bytes.ContainsRune(out, utf8.RuneError) {
			return nil, false
		}
		return out, true
	}
}

// pageLinks builds the Raw and Download links. A visitor who opened the page
// with ?password= carries it over, because those links replace the query; the
// visitor already holds it in the address bar and query strings are never
// logged. Every other way in (cookie, Basic auth, sign-in) needs nothing.
func pageLinks(r *http.Request, via string) (raw, download string) {
	prefix := "?"
	if via == "password_query" {
		prefix += url.Values{"password": {r.URL.Query().Get("password")}}.Encode() + "&"
	}
	link := func(key string) string { return prefix + key + "=1" }
	return link("raw"), link("download")
}

// servePage renders f as a page; via is how a restricted file was opened.
// It returns false, having written nothing, if f should be served raw
// instead (too large, or not decodable).
func (h *Handler) servePage(w http.ResponseWriter, r *http.Request, f files.File, via string) bool {
	if f.Size > maxRenderBytes {
		return false
	}
	obj, v, err := h.files.Open(r.Context(), f.ID, 0)
	if err != nil {
		h.notFound(w, r, err)
		return true
	}
	defer obj.Close()
	if v.Size > maxRenderBytes {
		return false
	}
	src, err := io.ReadAll(io.LimitReader(obj, maxRenderBytes+1))
	if err != nil {
		h.notFound(w, r, err)
		return true
	}
	src, ok := decodeMarkdown(src, v.ContentType)
	if !ok {
		return false
	}
	body, err := renderMarkdown(src)
	if err != nil {
		http.Error(w, "could not render this file", http.StatusInternalServerError)
		return true
	}
	rawLink, downloadLink := pageLinks(r, via)
	var page bytes.Buffer
	if err := markdownPage.Execute(&page, markdownData{
		Name: path.Base(f.Name), Size: humanSize(v.Size), Updated: v.CreatedAt.UTC().Format(time.DateOnly), Body: body,
		Raw: rawLink, Download: downloadLink,
	}); err != nil {
		http.Error(w, "could not render this file", http.StatusInternalServerError)
		return true
	}
	setPageHeaders(w)
	header := w.Header()
	header.Set("Content-Length", strconv.Itoa(page.Len()))
	header.Set("Content-Security-Policy", markdownCSP)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(page.Bytes())
	}
	return true
}

func humanSize(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d bytes", n)
	case n < 1000*1000:
		return fmt.Sprintf("%.1f KB", float64(n)/1000)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/1000/1000)
	}
}

type markdownData struct {
	Name, Size, Updated string
	Raw, Download       string
	Body                template.HTML
}

// markdownCSS is GitHub-like, follows the system light or dark theme, and is
// allowed by hash, so the page runs no script and loads nothing but images.
const markdownCSS = `
:root{color-scheme:light dark;--fg:#1f2328;--muted:#59636e;--bg:#fff;--canvas:#f6f8fa;--border:#d1d9e0;--link:#0969da;--code:rgba(129,139,152,.12)}
@media (prefers-color-scheme:dark){:root{--fg:#f0f6fc;--muted:#9198a1;--bg:#0d1117;--canvas:#151b23;--border:#3d444d;--link:#4493f8;--code:rgba(101,108,118,.2)}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans",Helvetica,Arial,sans-serif;-webkit-text-size-adjust:100%}
main{max-width:980px;margin:2rem auto;padding:0 1rem}
.file{border:1px solid var(--border);border-radius:6px;overflow:hidden}
.bar{display:flex;flex-wrap:wrap;gap:.5rem 1rem;align-items:center;justify-content:space-between;padding:.5rem 1rem;background:var(--canvas);border-bottom:1px solid var(--border);font-size:14px}
.name{font-weight:600;word-break:break-all}.meta{color:var(--muted);font-weight:400;margin-left:.5rem}
.actions{display:flex;gap:.5rem}
.actions a{padding:3px 12px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--fg);text-decoration:none;font-weight:500;line-height:20px}
.actions a:hover{background:var(--canvas)}
article{padding:2rem;word-wrap:break-word}
article>:first-child{margin-top:0}article>:last-child{margin-bottom:0}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
h1,h2,h3,h4,h5,h6{margin:1.5em 0 1rem;font-weight:600;line-height:1.25}
h1{font-size:2em;padding-bottom:.3em;border-bottom:1px solid var(--border)}
h2{font-size:1.5em;padding-bottom:.3em;border-bottom:1px solid var(--border)}
h3{font-size:1.25em}h4{font-size:1em}h5{font-size:.875em}h6{font-size:.85em;color:var(--muted)}
p,blockquote,ul,ol,dl,table,pre,details{margin:0 0 1rem}
ul,ol{padding-left:2em}li+li{margin-top:.25em}
li:has(>input[type=checkbox]),li:has(>p>input[type=checkbox]){list-style:none}li>input[type=checkbox],li>p>input[type=checkbox]{margin:0 .2em .25em -1.4em;vertical-align:middle}
blockquote{padding:0 1em;color:var(--muted);border-left:.25em solid var(--border)}
hr{height:.25em;margin:1.5rem 0;padding:0;border:0;background:var(--border)}
code,pre{font:85%/1.45 ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
code{padding:.2em .4em;border-radius:6px;background:var(--code)}
pre{padding:1rem;overflow:auto;border-radius:6px;background:var(--canvas)}
pre code{padding:0;background:none;font-size:100%}
table{display:block;width:max-content;max-width:100%;overflow:auto;border-collapse:collapse}
th,td{padding:6px 13px;border:1px solid var(--border)}th{font-weight:600}
tr:nth-child(2n){background:var(--canvas)}
img{max-width:100%;background:var(--bg)}
@media (max-width:600px){main{margin:0;padding:0}.file{border-radius:0;border-left:0;border-right:0}article{padding:1rem}}
`

var markdownCSP = "default-src 'none'; style-src 'sha256-" + func() string {
	sum := sha256.Sum256([]byte(markdownCSS))
	return base64.StdEncoding.EncodeToString(sum[:])
}() + "'; img-src 'self' https:; script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

var markdownPage = template.Must(template.New("markdown").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="robots" content="noindex"><title>{{.Name}}</title>
<style>` + markdownCSS + `</style></head>
<body><main><div class="file">
<div class="bar"><div><span class="name">{{.Name}}</span><span class="meta">{{.Size}} · {{.Updated}}</span></div>
<nav class="actions"><a href="{{.Raw}}">Raw</a><a href="{{.Download}}">Download</a></nav></div>
<article>{{.Body}}</article>
</div></main></body></html>
`))
