package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zachlatta/file-share/internal/files"
)

func TestServedRequestsAreLogged(t *testing.T) {
	e := newEnv(t)
	audio := e.upload(t, "episode.mp3", strings.Repeat("a", 1000), "")
	req := visitor(http.MethodGet, urlPath(audio)+"?token=leaky", "")
	req.Header.Set("Range", "bytes=200-499")
	rec := e.do(req)
	if rec.Code != http.StatusPartialContent || rec.Body.Len() != 300 {
		t.Fatalf("range = %d %d", rec.Code, rec.Body.Len())
	}
	// Audio and video skip the shared cache, so every range reaches the log.
	if cc := rec.Header().Get("Cache-Control"); cc != "private, no-cache" {
		t.Fatalf("audio Cache-Control = %q", cc)
	}
	e.do(visitor(http.MethodGet, urlPath(audio), ""))
	page := e.upload(t, "index.html", "<p>hi</p>", "")
	rec = e.do(visitor(http.MethodGet, urlPath(page), ""))
	if cc := rec.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "public") {
		t.Fatalf("page Cache-Control = %q", cc)
	}
	e.do(visitor(http.MethodGet, "/"+audio.Namespace+"/missing.mp3", "")) // 404s are not logged

	got, err := e.files.ListRequests(context.Background(), files.RequestQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("requests = %+v", got)
	}
	r := got[2]
	if r.FileID != audio.ID || r.Name != "episode.mp3" || r.Method != "GET" || r.Status != 206 || r.RangeStart != 200 ||
		r.BytesSent != 300 || r.Size != 1000 || r.IP != "203.0.113.9" || r.Country != "CA" ||
		r.UserAgent != "TestBrowser/1.0" || r.Referer != "https://chat.example/thread" {
		t.Fatalf("range request = %+v", r)
	}
	if got[1].Status != 200 || got[1].RangeStart != 0 || got[1].BytesSent != 1000 {
		t.Fatalf("full request = %+v", got[1])
	}
}

func TestAdminListening(t *testing.T) {
	e := newEnv(t)
	audio := e.upload(t, "episode.mp3", strings.Repeat("a", 1000), "")
	req := visitor(http.MethodGet, urlPath(audio), "")
	req.Header.Set("Range", "bytes=0-499")
	e.do(req)
	rec := adminGet(e, "/api/admin/listening?namespace="+audio.Namespace+"&buckets=2", adminToken)
	var out struct {
		Files []files.FileListening `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 || len(out.Files) != 1 ||
		out.Files[0].Coverage[0] != 1 || out.Files[0].Coverage[1] != 0 {
		t.Fatalf("listening: %d %s", rec.Code, rec.Body)
	}
	if rec := adminGet(e, "/api/admin/listening?since=yesterday", adminToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad since: %d", rec.Code)
	}
}
