package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zachlatta/file-share/internal/files"
)

func (e *env) api(method, target, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer curl:"+secret)
	if strings.HasPrefix(body, "{") {
		req.Header.Set("Content-Type", "application/json")
	}
	return e.do(req)
}

// Everything an agent does from a shell works with the static bearer alone:
// no OAuth flow just to change who can open a file or to download one.
func TestAPIManagesAndDownloadsFiles(t *testing.T) {
	e := newEmailEnv(t)
	f := e.uploadFor(t, "map.html", "<p>v1</p>", "pw", "zach@hackclub.com")

	// Download exact bytes of a restricted file, by ID or namespace/name.
	for _, ref := range []string{f.ID, url.PathEscape(f.Namespace + "/" + f.Name)} {
		rec := e.api(http.MethodGet, "/api/files/"+ref+"/content", "")
		if rec.Code != 200 || rec.Body.String() != "<p>v1</p>" || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("download %s: %d %q %q", ref, rec.Code, rec.Body, rec.Header().Get("Cache-Control"))
		}
	}
	if rec := e.do(httptest.NewRequest(http.MethodGet, "/api/files/"+f.ID+"/content", nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous download: %d", rec.Code)
	}

	// Replace only if nobody else has, then read the old version back.
	if rec := e.api(http.MethodPut, "/api/files/"+f.ID+"/content?expected_version=1", "<p>v2</p>"); rec.Code != 200 || decodeFile(t, rec).Version != 2 {
		t.Fatalf("replace at v1: %d %s", rec.Code, rec.Body)
	}
	rec := e.api(http.MethodPut, "/api/files/"+f.ID+"/content?expected_version=1", "<p>stale</p>")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "version 2") {
		t.Fatalf("stale replace: %d %s", rec.Code, rec.Body)
	}
	if rec := e.api(http.MethodPut, "/api/files/"+f.ID+"/content?expected_version=two", "x"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad expected_version: %d", rec.Code)
	}
	if rec := e.api(http.MethodGet, "/api/files/"+f.ID+"/content?version=1", ""); rec.Code != 200 || rec.Body.String() != "<p>v1</p>" {
		t.Fatalf("download v1: %d %q", rec.Code, rec.Body)
	}
	rec = e.api(http.MethodGet, "/api/files/"+f.ID+"/versions", "")
	var versions struct{ Versions []files.Version }
	_ = json.Unmarshal(rec.Body.Bytes(), &versions)
	if rec.Code != 200 || len(versions.Versions) != 2 || versions.Versions[0].Number != 2 {
		t.Fatalf("versions: %d %s", rec.Code, rec.Body)
	}
	if rec := e.api(http.MethodPost, "/api/files/"+f.ID+"/rollback?version=1", ""); rec.Code != 200 || decodeFile(t, rec).Version != 3 {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body)
	}

	// Change who can open it, its password and its name in one call.
	rec = e.api(http.MethodPatch, "/api/files/"+f.ID, `{"allowed_emails":["max@hackclub.com","@hackclub.org"],"password":"","name":"world.html"}`)
	g := decodeFile(t, rec)
	if rec.Code != 200 || g.HasPassword || g.Name != "world.html" || strings.Join(g.AllowedEmails, ",") != "@hackclub.org,max@hackclub.com" || g.Version != 3 {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	// Fields left out are left alone; an empty list makes it public.
	rec = e.api(http.MethodPatch, "/api/files/"+f.ID, `{"password":"new-pw"}`)
	if g := decodeFile(t, rec); rec.Code != 200 || !g.HasPassword || len(g.AllowedEmails) != 2 || g.Name != "world.html" {
		t.Fatalf("partial patch: %d %s", rec.Code, rec.Body)
	}
	rec = e.api(http.MethodPatch, "/api/files/"+f.ID, `{"allowed_emails":[],"password":""}`)
	if g := decodeFile(t, rec); rec.Code != 200 || g.Restricted() {
		t.Fatalf("unrestrict: %d %s", rec.Code, rec.Body)
	}
	for _, body := range []string{`{"allowed_emails":["not an email"]}`, `{"nmae":"typo.html"}`, `not json`, `{}`} {
		if rec := e.api(http.MethodPatch, "/api/files/"+f.ID, body); rec.Code != http.StatusBadRequest {
			t.Errorf("patch %s: %d %s", body, rec.Code, rec.Body)
		}
	}

	// Deleted files can still be downloaded by ID.
	if _, err := e.files.Delete(context.Background(), f.ID); err != nil {
		t.Fatal(err)
	}
	if rec := e.api(http.MethodGet, "/api/files/"+f.ID+"/content", ""); rec.Code != 200 {
		t.Fatalf("download deleted: %d", rec.Code)
	}
}
