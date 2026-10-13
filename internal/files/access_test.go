package files

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAccessLog(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "secret.txt", "x")
	g := h.upload(t, "", "other.txt", "y")
	events := []AccessEvent{
		{FileID: f.ID, Namespace: f.Namespace, Name: f.Name, Event: "denied", IP: "1.1.1.1", UserAgent: "curl/8", Status: 401},
		{FileID: f.ID, Namespace: f.Namespace, Name: f.Name, Event: "view", Via: "email", Email: "zach@hackclub.com", IP: "2.2.2.2", Country: "US", UserAgent: "Mozilla", Referer: "https://a.example/", Version: 1, Status: 200},
		{FileID: g.ID, Namespace: g.Namespace, Name: g.Name, Event: "view", Via: "password_cookie", IP: "2.2.2.2", Status: 200},
	}
	for i, e := range events {
		h.clock.t = h.clock.t.Add(time.Minute)
		if err := h.svc.RecordAccess(ctx, e); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	all, err := h.svc.ListAccess(ctx, AccessQuery{})
	if err != nil || len(all) != 3 || all[0].FileID != g.ID || all[2].Event != "denied" {
		t.Fatalf("list all (newest first): %+v %v", all, err)
	}
	if all[1].Email != "zach@hackclub.com" || all[1].Country != "US" || all[1].UserAgent != "Mozilla" || !all[1].At.Equal(h.clock.t.Add(-time.Minute)) {
		t.Fatalf("event fields: %+v", all[1])
	}
	byFile, _ := h.svc.ListAccess(ctx, AccessQuery{FileID: f.ID})
	if len(byFile) != 2 {
		t.Fatalf("by file: %d", len(byFile))
	}
	byIP, _ := h.svc.ListAccess(ctx, AccessQuery{Search: "2.2.2"})
	byEmail, _ := h.svc.ListAccess(ctx, AccessQuery{Search: "ZACH@"})
	views, _ := h.svc.ListAccess(ctx, AccessQuery{Event: "view"})
	if len(byIP) != 2 || len(byEmail) != 1 || len(views) != 2 {
		t.Fatalf("search ip %d email %d views %d", len(byIP), len(byEmail), len(views))
	}
	page, _ := h.svc.ListAccess(ctx, AccessQuery{Limit: 2})
	rest, _ := h.svc.ListAccess(ctx, AccessQuery{Before: page[1].ID})
	if len(page) != 2 || len(rest) != 1 || rest[0].Event != "denied" {
		t.Fatalf("paging: %d %d", len(page), len(rest))
	}
	// The log outlives the file: purging keeps the audit trail.
	if err := h.svc.PurgeFile(ctx, f.ID); err != nil {
		t.Fatal(err)
	}
	if after, _ := h.svc.ListAccess(ctx, AccessQuery{FileID: f.ID}); len(after) != 2 || after[0].Name != "secret.txt" {
		t.Fatalf("after purge: %+v", after)
	}
}

func TestRestrictedFiles(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.upload(t, "", "public.txt", "x")
	pw, _ := h.svc.Upload(ctx, UploadInput{Name: "pw.txt", Body: strings.NewReader("x"), Size: -1, Password: "hunter22"})
	em, _ := h.svc.Upload(ctx, UploadInput{Name: "em.txt", Body: strings.NewReader("x"), Size: -1, AllowedEmails: []string{"zach@hackclub.com"}})
	for _, e := range []AccessEvent{
		{FileID: em.ID, Event: "view", Email: "zach@hackclub.com", IP: "1.1.1.1"},
		{FileID: em.ID, Event: "view", Email: "zach@hackclub.com", IP: "1.1.1.1"},
		{FileID: em.ID, Event: "view", Email: "zach@hackclub.com", IP: "9.9.9.9"},
		{FileID: em.ID, Event: "denied", IP: "5.5.5.5"},
	} {
		h.clock.t = h.clock.t.Add(time.Minute)
		_ = h.svc.RecordAccess(ctx, e)
	}
	list, err := h.svc.RestrictedFiles(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("restricted files: %+v %v", list, err)
	}
	byName := map[string]RestrictedFile{}
	for _, r := range list {
		byName[r.Name] = r
	}
	got := byName["em.txt"]
	if got.Views != 3 || got.Denied != 1 || got.Viewers != 1 || got.LastViewedAt == nil || len(got.AllowedEmails) != 1 {
		t.Fatalf("em.txt summary: %+v", got)
	}
	if p := byName["pw.txt"]; !p.HasPassword || p.Views != 0 || p.LastViewedAt != nil || p.ID != pw.ID {
		t.Fatalf("pw.txt summary: %+v", p)
	}
}
