package files

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func sha(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func (h *harness) keysWithPrefix(prefix string) []string {
	var out []string
	for _, k := range h.blobs.Keys() {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// Identical bytes are stored once, under a key derived from their SHA-256,
// however many files, versions and namespaces hold them.
func TestIdenticalContentIsStoredOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	a := h.upload(t, "", "a.txt", "same bytes")
	b := h.upload(t, "", "b.txt", "same bytes")
	c := h.upload(t, a.Namespace, "c.bin", "same bytes")
	other := h.upload(t, "", "other.txt", "different bytes")
	d, err := h.svc.Replace(ctx, other.ID, ReplaceInput{Body: strings.NewReader("same bytes"), Size: -1})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"blobs/sha256/" + sha("different bytes"), "blobs/sha256/" + sha("same bytes")}
	slices.Sort(want)
	if got := h.keysWithPrefix(""); !slices.Equal(got, want) {
		t.Fatalf("stored keys = %v, want %v", got, want)
	}
	for _, f := range []File{a, b, c, d} {
		if got := h.read(t, f, 0); got != "same bytes" {
			t.Fatalf("%s = %q", f.Name, got)
		}
	}
	// Each file keeps its own content type even though the bytes are shared.
	if a.ContentType == c.ContentType {
		t.Fatalf("content types should differ by name: %q", a.ContentType)
	}
	// Only the first upload of each content copies it to its key.
	if n := h.flaky.copies.Load(); n != 2 {
		t.Fatalf("copies = %d, want 2", n)
	}
	var rows, refs int
	if err := h.svc.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM blobs), (SELECT count(*) FROM versions WHERE blob_key = $1)`,
		"blobs/sha256/"+sha("same bytes")).Scan(&rows, &refs); err != nil {
		t.Fatal(err)
	}
	if rows != 2 || refs != 4 {
		t.Fatalf("blobs rows = %d, refs = %d", rows, refs)
	}
}

// Chunked uploads and empty files go through the same content-addressed path.
func TestChunkedAndEmptyUploadsAreContentAddressed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const key = "0123456789abcdef0123456789abcdef"
	for i, chunk := range []string{"alpha-", "beta"} {
		if _, err := h.svc.PutPart(ctx, key, i+1, strings.NewReader(chunk), -1); err != nil {
			t.Fatal(err)
		}
	}
	f, err := h.svc.CompleteParts(ctx, key, 2, func(ctx context.Context, r io.Reader) (File, error) {
		return h.svc.Upload(ctx, UploadInput{Name: "joined.txt", Body: r, Size: -1})
	})
	if err != nil {
		t.Fatal(err)
	}
	h.upload(t, "", "plain.txt", "alpha-beta")
	h.upload(t, "", ".nojekyll", "")
	want := []string{"blobs/sha256/" + sha(""), "blobs/sha256/" + sha("alpha-beta")}
	slices.Sort(want)
	if got := h.keysWithPrefix(""); !slices.Equal(got, want) {
		t.Fatalf("stored keys = %v, want %v", got, want)
	}
	if h.read(t, f, 0) != "alpha-beta" {
		t.Fatal("chunked upload content wrong")
	}
}

// Every version is a lock on its blob. Two files share bytes; one expires
// after 15 days and the other after 30. The blob outlives the first file's
// purge and is deleted only after the last file holding it is purged.
func TestSharedBlobLivesUntilItsLastReferenceIsPurged(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	key := "blobs/sha256/" + sha("shared archive")
	short, err := h.svc.Upload(ctx, UploadInput{Name: "short.zip", Body: strings.NewReader("shared archive"), Size: -1, ExpiresAt: ptr(h.clock.t.Add(15 * 24 * time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	long, err := h.svc.Upload(ctx, UploadInput{Name: "long.zip", Body: strings.NewReader("shared archive"), Size: -1, ExpiresAt: ptr(h.clock.t.Add(30 * 24 * time.Hour))})
	if err != nil {
		t.Fatal(err)
	}

	// Day 16: short expires (soft delete). Day 46: short is purged.
	h.clock.t = h.clock.t.Add(16 * 24 * time.Hour)
	if _, err := h.svc.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	h.clock.t = h.clock.t.Add(30 * 24 * time.Hour)
	res, err := h.svc.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Get(ctx, short.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("short-lived file not purged: %v", err)
	}
	if res.Blobs != 0 || !slices.Equal(h.keysWithPrefix("blobs/"), []string{key}) {
		t.Fatalf("shared blob deleted while long.zip holds it: %+v %v", res, h.blobs.Keys())
	}
	// long expired on day 30 and is still restorable, with its bytes.
	if _, err := h.svc.Restore(ctx, long.ID); err != nil {
		t.Fatal(err)
	}
	if h.read(t, long, 0) != "shared archive" {
		t.Fatal("long.zip lost its bytes")
	}
	if _, err := h.svc.Delete(ctx, long.ID); err != nil {
		t.Fatal(err)
	}
	h.clock.t = h.clock.t.Add(31 * 24 * time.Hour)
	res, err = h.svc.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Blobs != 1 || len(h.blobs.Keys()) != 0 {
		t.Fatalf("blob kept after its last reference was purged: %+v %v", res, h.blobs.Keys())
	}
	var rows int
	if err := h.svc.db.QueryRow(ctx, `SELECT count(*) FROM blobs`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("blobs rows = %d, %v", rows, err)
	}
}

func ptr[T any](v T) *T { return &v }

// purge_file of one file must not take bytes another file still uses.
func TestPurgeFileKeepsBytesSharedWithAnotherFile(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	a := h.upload(t, "", "a.txt", "shared")
	b := h.upload(t, "", "b.txt", "shared")
	if err := h.svc.PurgeFile(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if h.read(t, b, 0) != "shared" {
		t.Fatal("purge_file deleted bytes another file uses")
	}
	if err := h.svc.PurgeFile(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if n := len(h.blobs.Keys()); n != 0 {
		t.Fatalf("blobs left after both purged: %v", h.blobs.Keys())
	}
}

// waitForBlockedLock waits until a session in this test's database is
// waiting on an advisory lock.
func (h *harness) waitForBlockedLock(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		if err := h.svc.db.QueryRow(context.Background(), `SELECT count(*) FROM pg_locks
			WHERE locktype = 'advisory' AND NOT granted
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no session ever waited on the blob lock")
}

type uploadResult struct {
	f   File
	err error
}

// A purge is deleting a blob when an upload of the same bytes arrives. The
// upload must wait for the delete to finish and then store the bytes again,
// rather than reference the object that is being deleted.
func TestUploadWaitsForPurgeDeletingTheSameBlob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	key := "blobs/sha256/" + sha("reused")
	old := h.upload(t, "", "old.txt", "reused")
	if _, err := h.svc.Delete(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	h.clock.t = h.clock.t.Add(31 * 24 * time.Hour)

	deleting, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	h.flaky.setHooks(nil, nil, func(k string) {
		if k == key {
			close(deleting)
			<-release
		}
	})
	purged := make(chan error, 1)
	go func() {
		_, err := h.svc.Purge(ctx)
		purged <- err
	}()
	<-deleting
	h.flaky.setHooks(nil, nil, nil)
	uploaded := make(chan uploadResult, 1)
	go func() {
		f, err := h.svc.Upload(ctx, UploadInput{Name: "new.txt", Body: strings.NewReader("reused"), Size: -1})
		uploaded <- uploadResult{f, err}
	}()
	h.waitForBlockedLock(t)
	releaseOnce.Do(func() { close(release) })
	if err := <-purged; err != nil {
		t.Fatal(err)
	}
	res := <-uploaded
	if res.err != nil {
		t.Fatal(res.err)
	}
	if got := h.read(t, res.f, 0); got != "reused" {
		t.Fatalf("new upload reads %q", got)
	}
}

// An upload has found the bytes it needs already stored when a purge removes
// the last other reference to them. The purge must wait for the upload to
// commit, see its reference, and keep the blob.
func TestPurgeWaitsForUploadReusingTheSameBlob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	key := "blobs/sha256/" + sha("reused")
	old := h.upload(t, "", "old.txt", "reused")
	if _, err := h.svc.Delete(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	h.clock.t = h.clock.t.Add(31 * 24 * time.Hour)

	statting, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	h.flaky.setHooks(func(k string) {
		if k == key {
			close(statting)
			<-release
		}
	}, nil, nil)
	uploaded := make(chan uploadResult, 1)
	go func() {
		f, err := h.svc.Upload(ctx, UploadInput{Name: "new.txt", Body: strings.NewReader("reused"), Size: -1})
		uploaded <- uploadResult{f, err}
	}()
	<-statting
	h.flaky.setHooks(nil, nil, nil)
	purged := make(chan PurgeResult, 1)
	go func() {
		res, err := h.svc.Purge(ctx)
		if err != nil {
			t.Error(err)
		}
		purged <- res
	}()
	h.waitForBlockedLock(t)
	releaseOnce.Do(func() { close(release) })
	res := <-uploaded
	if res.err != nil {
		t.Fatal(res.err)
	}
	if pr := <-purged; pr.Files != 1 || pr.Blobs != 0 {
		t.Fatalf("purge = %+v, want the old file purged and the blob kept", pr)
	}
	if got := h.read(t, res.f, 0); got != "reused" {
		t.Fatalf("new upload reads %q", got)
	}
}

// If the bytes of a recorded blob have gone missing from the store (a delete
// whose transaction then failed), the next upload of that content stores
// them again instead of trusting the database row.
func TestUploadRestoresMissingBytesOfAKnownBlob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	key := "blobs/sha256/" + sha("fragile")
	a := h.upload(t, "", "a.txt", "fragile")
	if err := h.svc.PurgeFile(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.db.Exec(ctx, `INSERT INTO blobs (key, sha256, size, created_at) VALUES ($1, $2, 7, now())`, key, sha("fragile")); err != nil {
		t.Fatal(err)
	}
	b := h.upload(t, "", "b.txt", "fragile")
	if h.read(t, b, 0) != "fragile" {
		t.Fatal("upload referenced bytes that were not stored")
	}
}

// Failed uploads leave nothing behind: not the staged bytes and not a new
// content object.
func TestFailedUploadsLeaveNoObjects(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "taken.txt", "v1")
	if _, err := h.svc.Replace(ctx, f.ID, ReplaceInput{Body: strings.NewReader("v2"), Size: -1, ExpectedVersion: 7}); !errors.Is(err, ErrConflict) {
		t.Fatalf("replace with a stale version: %v", err)
	}
	h.flaky.setHooks(nil, func(string, string) error { return errors.New("copy failed") }, nil)
	if _, err := h.svc.Upload(ctx, UploadInput{Name: "x.txt", Body: strings.NewReader("new bytes"), Size: -1}); err == nil {
		t.Fatal("upload succeeded although its bytes were not stored")
	}
	h.flaky.setHooks(nil, nil, nil)
	if got := h.keysWithPrefix(""); !slices.Equal(got, []string{"blobs/sha256/" + sha("v1")}) {
		t.Fatalf("keys after failed uploads = %v", got)
	}
}

// Staged bytes left by a crash between staging and attaching are swept once
// they are older than the grace period.
func TestPurgeSweepsStaleStagedUploads(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.blobs.Put(ctx, "staging/abandoned", strings.NewReader("x"), 1, "text/plain"); err != nil {
		t.Fatal(err)
	}
	h.clock.t = h.clock.t.Add(23 * time.Hour)
	if res, err := h.svc.Purge(ctx); err != nil || res.Orphans != 0 || len(h.blobs.Keys()) != 1 {
		t.Fatalf("fresh staging swept: %+v %v", res, err)
	}
	h.clock.t = h.clock.t.Add(2 * time.Hour)
	if res, err := h.svc.Purge(ctx); err != nil || res.Orphans != 1 || len(h.blobs.Keys()) != 0 {
		t.Fatalf("stale staging kept: %+v %v %v", res, err, h.blobs.Keys())
	}
}

// A blob row whose delete failed (storage down) is retried by the sweep.
func TestPurgeRetriesUnreferencedBlobRows(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "a.txt", "bytes")
	h.flaky.failDeletes.Store(true)
	if err := h.svc.PurgeFile(ctx, f.ID); err == nil {
		t.Fatal("purge_file with storage down reported success")
	}
	h.flaky.failDeletes.Store(false)
	h.clock.t = h.clock.t.Add(25 * time.Hour)
	res, err := h.svc.Purge(ctx)
	if err != nil || res.Orphans != 1 || len(h.blobs.Keys()) != 0 {
		t.Fatalf("sweep = %+v %v %v", res, err, h.blobs.Keys())
	}
	var rows int
	if err := h.svc.db.QueryRow(ctx, `SELECT count(*) FROM blobs`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("blobs rows = %d, %v", rows, err)
	}
}

// The database refuses a version that names a blob it has no record of, and
// refuses to forget a blob a version still uses.
func TestDatabaseEnforcesBlobReferences(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "a.txt", "bytes")
	if _, err := h.svc.db.Exec(ctx, `DELETE FROM blobs`); err == nil {
		t.Fatal("deleted a blob row a version references")
	}
	if _, err := h.svc.db.Exec(ctx, `UPDATE versions SET blob_key = 'blobs/unknown' WHERE file_id = $1`, f.ID); err == nil {
		t.Fatal("pointed a version at an unknown blob")
	}
}
