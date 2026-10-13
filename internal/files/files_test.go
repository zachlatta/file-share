package files

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/zachlatta/file-share/internal/blob"
	"github.com/zachlatta/file-share/internal/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type harness struct {
	svc   *Service
	blobs *blob.Memory
	clock *clock
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	c := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	blobs := blob.NewMemory()
	blobs.Now = c.now
	svc, err := Open(ctx, Config{
		DatabaseURL: pgtest.New(t),
		Blobs:       blobs,
		BaseURL:     "https://files.example.com",
		Retention:   30 * 24 * time.Hour,
		MaxBytes:    1 << 20,
		Now:         c.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return &harness{svc: svc, blobs: blobs, clock: c}
}

func (h *harness) upload(t *testing.T, ns, name, body string) File {
	t.Helper()
	f, err := h.svc.Upload(context.Background(), UploadInput{Namespace: ns, Name: name, Body: strings.NewReader(body), Size: -1, Client: "test"})
	if err != nil {
		t.Fatalf("upload %s: %v", name, err)
	}
	return f
}

func (h *harness) read(t *testing.T, f File, version int) string {
	t.Helper()
	obj, _, err := h.svc.Open(context.Background(), f.ID, version)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer obj.Close()
	data, _ := io.ReadAll(obj)
	return string(data)
}

func TestUploadCreatesUnguessableNamespace(t *testing.T) {
	h := newHarness(t)
	f := h.upload(t, "", "hello.txt", "hello world")
	ns, err := uuid.Parse(f.Namespace)
	if err != nil || ns.Version() != 4 {
		t.Fatalf("namespace %q is not a random UUID", f.Namespace)
	}
	if f.URL != "https://files.example.com/"+f.Namespace+"/hello.txt" {
		t.Fatalf("url = %q", f.URL)
	}
	if f.Size != 11 || f.Version != 1 || f.ContentType != "text/plain; charset=utf-8" || f.SHA256 != "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Fatalf("file = %+v", f)
	}
	if got := h.read(t, f, 0); got != "hello world" {
		t.Fatalf("content = %q", got)
	}
	g := h.upload(t, "", "hello.txt", "other")
	if g.Namespace == f.Namespace {
		t.Fatal("two uploads without a namespace share one")
	}
	// Lookup by public path.
	got, err := h.svc.Lookup(context.Background(), f.Namespace, "hello.txt")
	if err != nil || got.ID != f.ID {
		t.Fatalf("lookup: %+v %v", got, err)
	}
}

func TestUploadIntoExistingNamespace(t *testing.T) {
	h := newHarness(t)
	a := h.upload(t, "", "index.html", "<h1>hi</h1>")
	b := h.upload(t, a.Namespace, "assets/style.css", "body{}")
	if b.Namespace != a.Namespace || b.ContentType != "text/css; charset=utf-8" {
		t.Fatalf("b = %+v", b)
	}
	if a.ContentType != "text/html; charset=utf-8" {
		t.Fatalf("html content type = %q", a.ContentType)
	}
	_, err := h.svc.Upload(context.Background(), UploadInput{Namespace: a.Namespace, Name: "index.html", Body: strings.NewReader("dup"), Size: -1})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := h.svc.Upload(context.Background(), UploadInput{Namespace: "not-a-uuid", Name: "x", Body: strings.NewReader("x"), Size: -1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad namespace: %v", err)
	}
	list, err := h.svc.List(context.Background(), ListOptions{Namespace: a.Namespace})
	if err != nil || len(list) != 2 {
		t.Fatalf("list namespace: %d %v", len(list), err)
	}
}

func TestNameValidation(t *testing.T) {
	h := newHarness(t)
	for _, bad := range []string{"", "/abs", "a/../b", "a//b", "./x", "trailing/", "back\\slash", "nul\x00", strings.Repeat("a", 256), ".", ".."} {
		_, err := h.svc.Upload(context.Background(), UploadInput{Name: bad, Body: strings.NewReader("x"), Size: -1})
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("name %q accepted: %v", bad, err)
		}
	}
	h.upload(t, "", "dir/sub/photo of me.jpg", "x")
	h.upload(t, "", "ünïcødé.txt", "x")
}

func TestMaxBytes(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.Upload(context.Background(), UploadInput{Name: "big.bin", Body: strings.NewReader(strings.Repeat("x", 1<<20+1)), Size: -1})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize upload: %v", err)
	}
	if keys := h.blobs.Keys(); len(keys) != 0 {
		t.Fatalf("oversize upload left blobs %v", keys)
	}
}

func TestReplaceKeepsVersionHistory(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "notes.md", "v1")
	h.clock.t = h.clock.t.Add(time.Hour)
	f2, err := h.svc.Replace(ctx, f.ID, ReplaceInput{Body: strings.NewReader("version two"), Size: -1, Client: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if f2.ID != f.ID || f2.URL != f.URL || f2.Version != 2 || f2.Size != 11 {
		t.Fatalf("replaced = %+v", f2)
	}
	if h.read(t, f2, 0) != "version two" || h.read(t, f2, 1) != "v1" {
		t.Fatal("version contents wrong")
	}
	versions, err := h.svc.Versions(ctx, f.ID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("versions: %+v %v", versions, err)
	}
	if !versions[0].Current || versions[0].Number != 2 || versions[1].Current || versions[1].PurgeAt == nil {
		t.Fatalf("versions = %+v", versions)
	}
	if want := h.clock.t.Add(30 * 24 * time.Hour); !versions[1].PurgeAt.Equal(want) {
		t.Fatalf("purge at %v, want %v", versions[1].PurgeAt, want)
	}

	// Roll back to v1: becomes v3 with v1's bytes; history is preserved.
	f3, err := h.svc.Rollback(ctx, f.ID, 1, "test")
	if err != nil {
		t.Fatal(err)
	}
	if f3.Version != 3 || h.read(t, f3, 0) != "v1" {
		t.Fatalf("rollback = %+v", f3)
	}
	versions, _ = h.svc.Versions(ctx, f.ID)
	if len(versions) != 3 || !strings.Contains(versions[0].Note, "v1") {
		t.Fatalf("versions after rollback = %+v", versions)
	}
	if _, err := h.svc.Rollback(ctx, f.ID, 9, "test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback to missing version: %v", err)
	}
}

func TestDeleteAndRestore(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "report.pdf", "%PDF-1.4 fake")
	deleted, err := h.svc.Delete(ctx, f.ID)
	if err != nil || deleted.DeletedAt == nil || deleted.PurgeAt == nil {
		t.Fatalf("delete: %+v %v", deleted, err)
	}
	if _, err := h.svc.Lookup(ctx, f.Namespace, "report.pdf"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted file still served: %v", err)
	}
	live, _ := h.svc.List(ctx, ListOptions{})
	trash, _ := h.svc.List(ctx, ListOptions{Deleted: true})
	if len(live) != 0 || len(trash) != 1 {
		t.Fatalf("live=%d trash=%d", len(live), len(trash))
	}
	if _, err := h.svc.Delete(ctx, f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
	if _, err := h.svc.Replace(ctx, f.ID, ReplaceInput{Body: strings.NewReader("x"), Size: -1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replace deleted: %v", err)
	}

	restored, err := h.svc.Restore(ctx, f.ID)
	if err != nil || restored.DeletedAt != nil {
		t.Fatalf("restore: %+v %v", restored, err)
	}
	if got, err := h.svc.Lookup(ctx, f.Namespace, "report.pdf"); err != nil || got.ID != f.ID {
		t.Fatalf("restored lookup: %v", err)
	}

	// Restoring onto a name now used by another file conflicts.
	_, _ = h.svc.Delete(ctx, f.ID)
	h.upload(t, f.Namespace, "report.pdf", "new one")
	if _, err := h.svc.Restore(ctx, f.ID); !errors.Is(err, ErrExists) {
		t.Fatalf("restore over live name: %v", err)
	}
}

func TestPurgeEnforcesRetention(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	kept := h.upload(t, "", "kept.txt", "a1")
	_, _ = h.svc.Replace(ctx, kept.ID, ReplaceInput{Body: strings.NewReader("a2"), Size: -1})
	gone := h.upload(t, "", "gone.txt", "b1")
	_, _ = h.svc.Delete(ctx, gone.ID)
	rolled := h.upload(t, "", "rolled.txt", "c1")
	_, _ = h.svc.Replace(ctx, rolled.ID, ReplaceInput{Body: strings.NewReader("c2"), Size: -1})
	_, _ = h.svc.Rollback(ctx, rolled.ID, 1, "") // v3 shares v1's blob

	// Rollback reuses v1's blob, so there are 5 distinct blobs: a1 a2 b1 c1 c2.
	if n := len(h.blobs.Keys()); n != 5 {
		t.Fatalf("blobs before purge = %d", n)
	}

	// Nothing is purged inside the window.
	h.clock.t = h.clock.t.Add(29 * 24 * time.Hour)
	res, err := h.svc.Purge(ctx)
	if err != nil || res.Files != 0 || res.Versions != 0 {
		t.Fatalf("early purge: %+v %v", res, err)
	}

	h.clock.t = h.clock.t.Add(2 * 24 * time.Hour)
	res, err = h.svc.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// gone.txt (1 file, 1 version), kept v1, rolled v2 and v1 (v1's blob is still used by v3).
	if res.Files != 1 || res.Versions != 4 {
		t.Fatalf("purge result = %+v", res)
	}
	if _, err := h.svc.Get(ctx, gone.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purged file still exists: %v", err)
	}
	if h.read(t, kept, 0) != "a2" || h.read(t, rolled, 0) != "c1" {
		t.Fatal("current versions damaged by purge")
	}
	if n := len(h.blobs.Keys()); n != 2 {
		t.Fatalf("blobs after purge = %d, want 2 (a2, c1)", n)
	}
	vs, _ := h.svc.Versions(ctx, rolled.ID)
	if len(vs) != 1 || vs[0].Number != 3 {
		t.Fatalf("rolled versions = %+v", vs)
	}
}

func TestPermanentDelete(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "secret.txt", "oops")
	_, _ = h.svc.Replace(ctx, f.ID, ReplaceInput{Body: strings.NewReader("oops2"), Size: -1})
	if err := h.svc.PurgeFile(ctx, f.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Get(ctx, f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after purge: %v", err)
	}
	if n := len(h.blobs.Keys()); n != 0 {
		t.Fatalf("blobs left: %d", n)
	}
}

func TestPasswords(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f, err := h.svc.Upload(ctx, UploadInput{Name: "private.txt", Body: strings.NewReader("shh"), Size: -1, Password: "hunter22"})
	if err != nil || !f.HasPassword {
		t.Fatalf("upload with password: %+v %v", f, err)
	}
	if !h.svc.CheckPassword(f, "hunter22") || h.svc.CheckPassword(f, "wrong") || h.svc.CheckPassword(f, "") {
		t.Fatal("password check wrong")
	}
	f, err = h.svc.SetPassword(ctx, f.ID, "")
	if err != nil || f.HasPassword || !h.svc.CheckPassword(f, "") {
		t.Fatalf("clear password: %+v %v", f, err)
	}
	f, err = h.svc.SetPassword(ctx, f.ID, "new-pass")
	if err != nil || !f.HasPassword || !h.svc.CheckPassword(f, "new-pass") {
		t.Fatalf("set password: %+v %v", f, err)
	}
	if f.PasswordStamp == "" {
		t.Fatal("password stamp missing")
	}
	// Passwords survive replace.
	f, _ = h.svc.Replace(ctx, f.ID, ReplaceInput{Body: strings.NewReader("v2"), Size: -1})
	if !f.HasPassword {
		t.Fatal("replace dropped password")
	}
}

func TestRename(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "draft.txt", "x")
	h.upload(t, f.Namespace, "taken.txt", "y")
	if _, err := h.svc.Rename(ctx, f.ID, "taken.txt"); !errors.Is(err, ErrExists) {
		t.Fatalf("rename onto existing: %v", err)
	}
	r, err := h.svc.Rename(ctx, f.ID, "final.txt")
	if err != nil || r.Name != "final.txt" || !strings.HasSuffix(r.URL, "/final.txt") {
		t.Fatalf("rename: %+v %v", r, err)
	}
}

func TestResolve(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "a b.txt", "x")
	for _, ref := range []string{f.ID, f.URL, "https://files.example.com/" + f.Namespace + "/a%20b.txt", f.Namespace + "/a b.txt"} {
		got, err := h.svc.Resolve(ctx, ref)
		if err != nil || got.ID != f.ID {
			t.Errorf("resolve %q: %v", ref, err)
		}
	}
	if _, err := h.svc.Resolve(ctx, uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("resolve missing: %v", err)
	}
	// Deleted files resolve by ID (to restore them).
	_, _ = h.svc.Delete(ctx, f.ID)
	if got, err := h.svc.Resolve(ctx, f.ID); err != nil || got.DeletedAt == nil {
		t.Fatalf("resolve deleted by id: %v", err)
	}
}

func TestListSearchAndStats(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.upload(t, "", "cat.png", "meow")
	h.clock.t = h.clock.t.Add(time.Minute)
	h.upload(t, "", "dog.png", "woof!")
	list, _ := h.svc.List(ctx, ListOptions{Query: "dog"})
	if len(list) != 1 || list[0].Name != "dog.png" {
		t.Fatalf("search = %+v", list)
	}
	all, _ := h.svc.List(ctx, ListOptions{})
	if len(all) != 2 || all[0].Name != "dog.png" {
		t.Fatalf("list should be newest first: %+v", all)
	}
	stats, err := h.svc.Stats(ctx)
	if err != nil || stats.Files != 2 || stats.Bytes != 9 {
		t.Fatalf("stats = %+v %v", stats, err)
	}
	names := []string{}
	for _, f := range all {
		names = append(names, f.Name)
	}
	if !slices.Contains(names, "cat.png") {
		t.Fatal("cat missing")
	}
}

func TestChunkedUploads(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const key = "0123456789abcdef0123456789abcdef"
	for i, chunk := range []string{"alpha-", "beta-", "gamma"} {
		if _, err := h.svc.PutPart(ctx, key, i+1, strings.NewReader(chunk), -1); err != nil {
			t.Fatalf("part %d: %v", i+1, err)
		}
	}
	if _, err := h.svc.PutPart(ctx, key, 0, strings.NewReader("x"), -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("part 0: %v", err)
	}
	if _, err := h.svc.PutPart(ctx, "../evil", 1, strings.NewReader("x"), -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad key: %v", err)
	}
	// Completing with a missing part fails and keeps the parts.
	_, err := h.svc.CompleteParts(ctx, key, 4, func(r io.Reader) (File, error) { t.Fatal("assembled with a missing part"); return File{}, nil })
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing part: %v", err)
	}
	f, err := h.svc.CompleteParts(ctx, key, 3, func(r io.Reader) (File, error) {
		return h.svc.Upload(ctx, UploadInput{Name: "joined.txt", Body: r, Size: -1})
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := h.read(t, f, 0); got != "alpha-beta-gamma" || f.Size != 16 {
		t.Fatalf("assembled = %q (%d bytes)", got, f.Size)
	}
	if n := len(h.blobs.Keys()); n != 1 {
		t.Fatalf("parts not cleaned up: %v", h.blobs.Keys())
	}
}

func TestPurgeRemovesAbandonedParts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.PutPart(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, strings.NewReader("orphan"), -1); err != nil {
		t.Fatal(err)
	}
	h.clock.t = h.clock.t.Add(23 * time.Hour)
	if res, _ := h.svc.Purge(ctx); res.Parts != 0 {
		t.Fatalf("fresh part purged: %+v", res)
	}
	h.clock.t = h.clock.t.Add(2 * time.Hour)
	res, err := h.svc.Purge(ctx)
	if err != nil || res.Parts != 1 || len(h.blobs.Keys()) != 0 {
		t.Fatalf("stale part not purged: %+v %v %v", res, err, h.blobs.Keys())
	}
}
