package files

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUploadLinkIsSingleUseAndCarriesSettings(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{
		Name: "report.pdf", Password: "pw-1", AllowedEmails: []string{"Zach@HackClub.com"},
		Client: "claude", ExpiresAt: h.clock.t.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The namespace is chosen up front, so the final URL is known before upload.
	if link.Namespace == "" || link.URL != "https://files.example.com/"+link.Namespace+"/report.pdf" {
		t.Fatalf("link = %+v", link)
	}
	f, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Name: "ignored.bin", Body: strings.NewReader("%PDF-1.7"), Size: -1})
	if err != nil {
		t.Fatal(err)
	}
	if f.URL != link.URL || !f.HasPassword || !h.svc.CheckPassword(f, "pw-1") || len(f.AllowedEmails) != 1 || f.AllowedEmails[0] != "zach@hackclub.com" {
		t.Fatalf("file = %+v", f)
	}
	if v, _ := h.svc.Versions(ctx, f.ID); v[0].CreatedBy != "claude" {
		t.Fatalf("created_by = %q", v[0].CreatedBy)
	}
	if _, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("again"), Size: -1}); !errors.Is(err, ErrLinkUsed) {
		t.Fatalf("second use: %v", err)
	}
	if _, err := h.svc.UploadLink(ctx, link.ID); !errors.Is(err, ErrLinkUsed) {
		t.Fatalf("lookup after use: %v", err)
	}
}

func TestUploadLinkWithoutNameTakesUploaderName(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{ExpiresAt: h.clock.t.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if link.URL != "" {
		t.Fatalf("url is unknown until the name is: %q", link.URL)
	}
	// A failed attempt (no name) releases the link so it can be retried.
	if _, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("x"), Size: -1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nameless upload: %v", err)
	}
	f, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Name: "photo.jpg", Body: strings.NewReader("x"), Size: -1})
	if err != nil {
		t.Fatal(err)
	}
	if f.Namespace != link.Namespace || f.Name != "photo.jpg" || f.HasPassword {
		t.Fatalf("file = %+v", f)
	}
}

func TestUploadLinkReplacesFile(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "a.txt", "v1")
	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{FileID: f.ID, ExpiresAt: h.clock.t.Add(time.Hour)})
	if err != nil || link.URL != f.URL {
		t.Fatalf("link = %+v %v", link, err)
	}
	g, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("v2"), Size: -1})
	if err != nil || g.ID != f.ID || g.Version != 2 {
		t.Fatalf("replace = %+v %v", g, err)
	}
	if _, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{FileID: f.ID, Password: "x", ExpiresAt: h.clock.t.Add(time.Hour)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replace link with settings: %v", err)
	}
}

func TestUploadLinkValidationAndExpiry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	exp := h.clock.t.Add(time.Hour)
	existing := h.upload(t, "", "taken.txt", "x")
	for name, in := range map[string]UploadLinkInput{
		"bad name":      {Name: "../x", ExpiresAt: exp},
		"bad namespace": {Namespace: "nope", ExpiresAt: exp},
		"bad email":     {AllowedEmails: []string{"not an email"}, ExpiresAt: exp},
	} {
		if _, err := h.svc.CreateUploadLink(ctx, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{Namespace: existing.Namespace, Name: "taken.txt", ExpiresAt: exp}); !errors.Is(err, ErrExists) {
		t.Errorf("taken name: %v", err)
	}
	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{Name: "late.txt", ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	h.clock.t = h.clock.t.Add(2 * time.Hour)
	if _, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("x"), Size: -1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired link: %v", err)
	}
	res, err := h.svc.Purge(ctx)
	if err != nil || res.Links != 1 {
		t.Fatalf("purge expired links: %+v %v", res, err)
	}
	if _, err := h.svc.UploadLink(ctx, "not-a-uuid"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
}

func TestReplaceLinkWithExpectedVersion(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "db.duckdb", "v1")
	expires := h.clock.t.Add(time.Hour)
	if _, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{FileID: f.ID, ExpectedVersion: 2, ExpiresAt: expires}); !errors.Is(err, ErrConflict) {
		t.Fatalf("link for a version the file is not at: %v", err)
	}
	if _, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{ExpectedVersion: 1, ExpiresAt: expires}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected version on a new-file link: %v", err)
	}
	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{FileID: f.ID, ExpectedVersion: 1, ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	// Another writer gets in first.
	if _, err := h.svc.Replace(ctx, f.ID, ReplaceInput{Body: strings.NewReader("v2"), Size: -1}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("stale"), Size: -1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale link upload: %v", err)
	}
	if got := h.read(t, f, 0); got != "v2" {
		t.Fatalf("current = %q", got)
	}
}
