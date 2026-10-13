package web

import (
	"crypto/rand"
	"crypto/subtle"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zachlatta/file-share/internal/auth"
	"github.com/zachlatta/file-share/internal/files"
)

const (
	// stateCookieName holds the nonce of a sign-in in progress, so the
	// callback only completes in the browser that started it.
	stateCookieName = "fs_hca_state"
	loginStateTTL   = 10 * time.Minute
	emailSessionTTL = 30 * 24 * time.Hour
)

// sessionCookieName is the per-namespace cookie that holds a signed-in email.
func sessionCookieName(namespace string) string {
	return "fse_" + strings.ReplaceAll(namespace, "-", "")
}

// sessionEmail returns the email signed in for namespace, or "".
func (h *Handler) sessionEmail(r *http.Request, namespace string) string {
	c, err := r.Cookie(sessionCookieName(namespace))
	if err != nil {
		return ""
	}
	email, err := h.auth.VerifyEmailSession(c.Value, namespace)
	if err != nil {
		return ""
	}
	return email
}

// loginStart sends the visitor to Hack Club Auth. next is the file path to
// return to; switch=1 forces a fresh login to change accounts.
func (h *Handler) loginStart(w http.ResponseWriter, r *http.Request) {
	if h.hca == nil {
		http.NotFound(w, r)
		return
	}
	next, _, ok := localFilePath(r.URL.Query().Get("next"))
	if !ok {
		renderMessage(w, http.StatusBadRequest, "Invalid sign-in link", "That sign-in link does not point to a file.", "")
		return
	}
	nonce := rand.Text()
	state := h.auth.SignLoginState(auth.LoginState{Next: next, Nonce: nonce}, loginStateTTL)
	http.SetCookie(w, &http.Cookie{
		Name: stateCookieName, Value: nonce, Path: "/oauth/callback", MaxAge: int(loginStateTTL.Seconds()),
		HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, h.hca.AuthorizeURL(state, r.URL.Query().Get("switch") == "1"), http.StatusFound)
}

// loginCallback finishes a Hack Club Auth sign-in and stores the verified
// email in a cookie for the file's namespace.
func (h *Handler) loginCallback(w http.ResponseWriter, r *http.Request) {
	if h.hca == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	st, err := h.auth.VerifyLoginState(q.Get("state"))
	c, cookieErr := r.Cookie(stateCookieName)
	if err != nil || cookieErr != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(st.Nonce)) != 1 {
		renderMessage(w, http.StatusBadRequest, "Sign-in expired", "This sign-in is invalid or has expired. Go back to the file and sign in again.", "")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookieName, Path: "/oauth/callback", MaxAge: -1, HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode})
	_, namespace, _ := localFilePath(st.Next)
	if q.Get("error") != "" {
		renderMessage(w, http.StatusBadRequest, "Sign-in cancelled", "Sign-in with Hack Club was cancelled.", st.Next)
		return
	}
	email, err := h.hca.Email(r.Context(), q.Get("code"))
	if err != nil {
		renderMessage(w, http.StatusBadGateway, "Sign-in failed", "Hack Club Auth did not confirm your email address. Please try again.", st.Next)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName(namespace), Value: h.auth.SignEmailSession(namespace, email, emailSessionTTL),
		Path: "/" + namespace + "/", MaxAge: int(emailSessionTTL.Seconds()),
		HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, st.Next, http.StatusSeeOther)
}

// localFilePath accepts only a path of the form /<namespace-uuid>/<rest>, so
// a sign-in can never redirect off-site. It returns the escaped path and the
// canonical namespace.
func localFilePath(next string) (string, string, bool) {
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, `\`) {
		return "", "", false
	}
	ns, _, ok := strings.Cut(u.Path[1:], "/")
	parsed, err := uuid.Parse(ns)
	if !ok || err != nil || parsed.String() != ns {
		return "", "", false
	}
	return u.EscapedPath(), ns, true
}

type gateData struct {
	Name       string
	Password   bool
	Email      bool
	LoginURL   string
	SwitchURL  string
	SignedInAs string
	Error      string
}

// renderGate shows the page for a restricted file: a Hack Club sign-in
// button when the file has allowed emails, and a password form when it has a
// password. Either one opens the file.
func (h *Handler) renderGate(w http.ResponseWriter, r *http.Request, f files.File, message string) {
	data := gateData{Name: path.Base(f.Name), Password: f.HasPassword, Error: message}
	status := http.StatusUnauthorized
	if len(f.AllowedEmails) > 0 && h.hca != nil {
		next := url.QueryEscape(r.URL.EscapedPath())
		data.Email = true
		data.LoginURL = "/oauth/hackclub?next=" + next
		data.SwitchURL = "/oauth/hackclub?switch=1&next=" + next
		if data.SignedInAs = h.sessionEmail(r, f.Namespace); data.SignedInAs != "" {
			status = http.StatusForbidden
		}
	}
	setPageHeaders(w)
	w.WriteHeader(status)
	_ = gatePage.Execute(w, data)
}

func setPageHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Frame-Options", "DENY")
}

func renderMessage(w http.ResponseWriter, status int, title, message, back string) {
	setPageHeaders(w)
	w.WriteHeader(status)
	_ = messagePage.Execute(w, map[string]string{"Title": title, "Message": message, "Back": back})
}

const pageStyle = `<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:28rem;margin:15vh auto;padding:0 1rem;color:#172026}input{display:block;width:100%;box-sizing:border-box;margin:.5rem 0 1rem;padding:.7rem;font:inherit;border:1px solid #b8c1cc;border-radius:6px}button,.button{display:inline-block;padding:.7rem 1rem;font:inherit;border:0;border-radius:6px;background:#172026;color:#fff;cursor:pointer;text-decoration:none}.hackclub{background:#ec3750}.error{color:#a00}.or{margin:1.5rem 0;color:#5a6b78}.hint{font-size:.9rem;color:#5a6b78}</style>`

var gatePage = template.Must(template.New("gate").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Access required</title>
` + pageStyle + `</head>
<body><h1>🔒 {{.Name}}</h1>
{{if .Email}}{{if .SignedInAs}}<p class="error">You're signed in as <strong>{{.SignedInAs}}</strong>, which doesn't have access to this file.</p>
<p><a class="button hackclub" href="{{.SwitchURL}}">Sign in with a different account</a></p>
{{else}}<p>This file is shared with specific people. Sign in with Hack Club to open it.</p>
<p><a class="button hackclub" href="{{.LoginURL}}">Sign in with Hack Club</a></p>{{end}}{{end}}
{{if .Password}}{{if .Email}}<p class="or">Or enter the password.</p>{{else}}<p>This file is password protected.</p>{{end}}
{{with .Error}}<p class="error">{{.}}</p>{{end}}
<form method="post"><label for="password">Password</label><input id="password" name="password" type="password" {{if not .Email}}autofocus {{end}}required autocomplete="current-password"><button type="submit">Open</button></form>
{{else if not .Email}}<p>This file is shared with specific people, but sign-in is not available right now.</p>{{end}}
</body></html>`))

var messagePage = template.Must(template.New("message").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>{{.Title}}</title>
` + pageStyle + `</head>
<body><h1>{{.Title}}</h1><p>{{.Message}}</p>{{with .Back}}<p><a href="{{.}}">Back to the file</a></p>{{end}}</body></html>`))
