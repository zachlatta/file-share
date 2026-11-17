package files

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/zachlatta/file-share/internal/blob"
)

// legacyize rewrites storage the way the server stored it before content
// addressing: every version gets its own object under a random key, even
// when the bytes are the same.
func (h *harness) legacyize(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	rows, err := h.svc.db.Query(ctx, `SELECT file_id::text, number, blob_key, sha256, size FROM versions ORDER BY file_id, number`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		id, key, sum string
		number       int
		size         int64
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.number, &r.key, &r.sum, &r.size); err != nil {
			t.Fatal(err)
		}
		all = append(all, r)
	}
	content := map[string]bool{}
	for _, r := range all {
		legacy := "blobs/" + uuid.NewString()
		if err := h.blobs.Copy(ctx, r.key, legacy); err != nil {
			t.Fatal(err)
		}
		content[r.key] = true
		if _, err := h.svc.db.Exec(ctx, `INSERT INTO blobs (key, sha256, size, created_at) VALUES ($1, $2, $3, $4)`, legacy, r.sum, r.size, h.clock.t); err != nil {
			t.Fatal(err)
		}
		if _, err := h.svc.db.Exec(ctx, `UPDATE versions SET blob_key = $3 WHERE file_id = $1 AND number = $2`, r.id, r.number, legacy); err != nil {
			t.Fatal(err)
		}
	}
	for key := range content {
		if _, err := h.svc.db.Exec(ctx, `DELETE FROM blobs WHERE key = $1`, key); err != nil {
			t.Fatal(err)
		}
		_ = h.blobs.Delete(ctx, key)
	}
}

func (h *harness) versionKeys(t *testing.T) []string {
	t.Helper()
	keys, err := h.svc.blobKeys(context.Background(), `SELECT blob_key FROM versions ORDER BY blob_key`)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// Four versions: "dup" twice in two files, "solo", and "solo v2", stored
// under legacy keys.
func legacyFixture(t *testing.T) (*harness, []File) {
	h := newHarness(t)
	a := h.upload(t, "", "a.txt", "dup")
	b := h.upload(t, "", "b.txt", "dup")
	c := h.upload(t, "", "c.txt", "solo")
	c2, err := h.svc.Replace(context.Background(), c.ID, ReplaceInput{Body: strings.NewReader("solo v2"), Size: -1})
	if err != nil {
		t.Fatal(err)
	}
	h.legacyize(t)
	h.flaky.copies.Store(0)
	return h, []File{a, b, c2}
}

func (h *harness) readOnly(t *testing.T) *Service {
	t.Helper()
	ro, err := Open(context.Background(), Config{DatabaseURL: h.dbURL, Blobs: blob.ReadOnly(h.flaky), BaseURL: "https://files.example.com", ReadOnly: true, Now: h.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ro.Close)
	return ro
}

func TestMigrateBlobsDryRunChangesNothing(t *testing.T) {
	h, _ := legacyFixture(t)
	ctx := context.Background()
	before, keysBefore := h.versionKeys(t), h.keysWithPrefix("")
	ro := h.readOnly(t)
	rep, err := ro.MigrateBlobs(ctx, MigrateBlobsOptions{DryRun: true, Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	want := MigrateBlobsReport{DryRun: true, LegacyObjects: 4, LegacyBytes: 3 + 3 + 4 + 7, DistinctContents: 3, CopyBytes: 3 + 4 + 7, SavedBytes: 3, Remaining: 4}
	if !reflect.DeepEqual(rep, want) {
		t.Fatalf("dry run = %+v, want %+v", rep, want)
	}
	if !slices.Equal(h.versionKeys(t), before) || !slices.Equal(h.keysWithPrefix(""), keysBefore) {
		t.Fatal("dry run changed storage")
	}
	// The read-only service cannot write, even by mistake.
	if _, err := ro.Upload(ctx, UploadInput{Name: "x.txt", Body: strings.NewReader("x"), Size: -1}); err == nil {
		t.Fatal("read-only service uploaded a file")
	}
	if _, err := ro.MigrateBlobs(ctx, MigrateBlobsOptions{}); err == nil {
		t.Fatal("read-only service ran a real migration")
	}
}

func TestMigrateBlobsMovesLegacyObjectsToContentKeys(t *testing.T) {
	h, files := legacyFixture(t)
	ctx := context.Background()
	legacy := h.versionKeys(t)
	rep, err := h.svc.MigrateBlobs(ctx, MigrateBlobsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := MigrateBlobsReport{LegacyObjects: 4, LegacyBytes: 17, DistinctContents: 3, CopyBytes: 14, SavedBytes: 3, Migrated: 4, Copied: 3, Reused: 1}
	if !reflect.DeepEqual(rep, want) {
		t.Fatalf("migration = %+v, want %+v", rep, want)
	}
	for _, key := range h.versionKeys(t) {
		if !isContentKey(key) {
			t.Fatalf("version still at %s", key)
		}
	}
	wantContent := []string{contentKey(sha("dup")), contentKey(sha("solo")), contentKey(sha("solo v2"))}
	slices.Sort(wantContent)
	if got := h.keysWithPrefix(contentPrefix); !slices.Equal(got, wantContent) {
		t.Fatalf("content keys = %v", got)
	}
	// Old objects stay until cleanup.
	for _, key := range legacy {
		if _, err := h.blobs.Stat(ctx, key); err != nil {
			t.Fatalf("legacy object %s removed: %v", key, err)
		}
	}
	if h.read(t, files[0], 0) != "dup" || h.read(t, files[1], 0) != "dup" || h.read(t, files[2], 1) != "solo" || h.read(t, files[2], 0) != "solo v2" {
		t.Fatal("content changed by migration")
	}
	// Running again is a no-op.
	rep, err = h.svc.MigrateBlobs(ctx, MigrateBlobsOptions{})
	if err != nil || !reflect.DeepEqual(rep, MigrateBlobsReport{}) {
		t.Fatalf("second run = %+v, %v", rep, err)
	}
	// Uploading migrated content again reuses its blob.
	h.upload(t, "", "d.txt", "solo")
	if n := h.flaky.copies.Load(); n != 3 {
		t.Fatalf("copies = %d, want 3", n)
	}
}

// A run that dies midway leaves every version readable, and running it
// again finishes the job.
func TestMigrateBlobsResumesAfterInterruption(t *testing.T) {
	h, files := legacyFixture(t)
	ctx := context.Background()
	var copies atomic.Int32
	h.flaky.setHooks(nil, func(src, dst string) error {
		// Reads keep working while a migration is in flight.
		for _, f := range files {
			h.read(t, f, 0)
		}
		if copies.Add(1) == 2 {
			return errors.New("connection reset")
		}
		return nil
	}, nil)
	if _, err := h.svc.MigrateBlobs(ctx, MigrateBlobsOptions{}); err == nil {
		t.Fatal("interrupted run reported success")
	}
	h.flaky.setHooks(nil, nil, nil)
	migrated := 0
	for _, key := range h.versionKeys(t) {
		if isContentKey(key) {
			migrated++
		}
	}
	if migrated == 0 || migrated == 4 {
		t.Fatalf("migrated %d of 4 before the failure", migrated)
	}
	for _, f := range files {
		h.read(t, f, 0)
	}
	rep, err := h.svc.MigrateBlobs(ctx, MigrateBlobsOptions{})
	if err != nil || rep.Migrated != 4-migrated || rep.Remaining != 0 {
		t.Fatalf("resumed run = %+v, %v", rep, err)
	}
	if h.read(t, files[0], 0) != "dup" || h.read(t, files[2], 0) != "solo v2" {
		t.Fatal("content changed by migration")
	}
}

// --limit migrates a few objects at a time, so a first run can be tiny.
func TestMigrateBlobsLimit(t *testing.T) {
	h, _ := legacyFixture(t)
	rep, err := h.svc.MigrateBlobs(context.Background(), MigrateBlobsOptions{Limit: 1})
	if err != nil || rep.Migrated != 1 || rep.Remaining != 3 {
		t.Fatalf("limited run = %+v, %v", rep, err)
	}
}

// Objects whose bytes do not match their recorded hash, or that are gone,
// are reported and left exactly as they are.
func TestMigrateBlobsSkipsCorruptAndMissingObjects(t *testing.T) {
	h, files := legacyFixture(t)
	ctx := context.Background()
	var corrupt, missing string
	for _, key := range h.versionKeys(t) {
		var name string
		if err := h.svc.db.QueryRow(ctx, `SELECT f.name FROM versions v JOIN files f ON f.id = v.file_id WHERE v.blob_key = $1`, key).Scan(&name); err != nil {
			t.Fatal(err)
		}
		switch name {
		case "a.txt":
			corrupt = key
		case "b.txt":
			missing = key
		}
	}
	if err := h.blobs.Delete(ctx, corrupt); err != nil {
		t.Fatal(err)
	}
	if err := h.blobs.Put(ctx, corrupt, strings.NewReader("DUP"), 3, "text/plain"); err != nil {
		t.Fatal(err)
	}
	if err := h.blobs.Delete(ctx, missing); err != nil {
		t.Fatal(err)
	}
	dry, err := h.readOnly(t).MigrateBlobs(ctx, MigrateBlobsOptions{DryRun: true, Verify: true})
	if err != nil || !slices.Equal(dry.Mismatched, []string{corrupt}) || !slices.Equal(dry.Missing, []string{missing}) {
		t.Fatalf("dry run = %+v, %v", dry, err)
	}
	rep, err := h.svc.MigrateBlobs(ctx, MigrateBlobsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Migrated != 2 || rep.Remaining != 2 || !slices.Equal(rep.Mismatched, []string{corrupt}) || !slices.Equal(rep.Missing, []string{missing}) {
		t.Fatalf("migration = %+v", rep)
	}
	keys := h.versionKeys(t)
	if !slices.Contains(keys, corrupt) || !slices.Contains(keys, missing) {
		t.Fatalf("skipped objects were repointed: %v", keys)
	}
	if h.read(t, files[2], 0) != "solo v2" {
		t.Fatal("good object not migrated")
	}
}

// Migrated legacy objects are not swept as orphans; cleanup-legacy-blobs
// deletes them only with confirm, and only once nothing references them.
func TestLegacyObjectsAreKeptUntilConfirmedCleanup(t *testing.T) {
	h, files := legacyFixture(t)
	ctx := context.Background()
	legacy := h.versionKeys(t)
	if _, err := h.svc.MigrateBlobs(ctx, MigrateBlobsOptions{}); err != nil {
		t.Fatal(err)
	}
	h.clock.t = h.clock.t.Add(48 * time.Hour)
	if res, err := h.svc.Purge(ctx); err != nil || res.Orphans != 0 {
		t.Fatalf("purge = %+v, %v", res, err)
	}
	for _, key := range legacy {
		if _, err := h.blobs.Stat(ctx, key); err != nil {
			t.Fatalf("purge removed legacy object %s: %v", key, err)
		}
	}
	dry, err := h.svc.CleanupLegacyBlobs(ctx, false)
	if err != nil || dry.Pending != 4 || dry.PendingBytes != 17 || dry.Deleted != 0 {
		t.Fatalf("cleanup without confirm = %+v, %v", dry, err)
	}
	for _, key := range legacy {
		if _, err := h.blobs.Stat(ctx, key); err != nil {
			t.Fatalf("cleanup without confirm removed %s", key)
		}
	}
	rep, err := h.svc.CleanupLegacyBlobs(ctx, true)
	if err != nil || rep.Deleted != 4 || rep.DeletedBytes != 17 {
		t.Fatalf("cleanup = %+v, %v", rep, err)
	}
	if got := h.keysWithPrefix(""); len(got) != 3 {
		t.Fatalf("keys after cleanup = %v", got)
	}
	if h.read(t, files[0], 0) != "dup" || h.read(t, files[2], 1) != "solo" {
		t.Fatal("cleanup damaged migrated content")
	}
	if again, err := h.svc.CleanupLegacyBlobs(ctx, true); err != nil || again.Pending != 0 || again.Deleted != 0 {
		t.Fatalf("second cleanup = %+v, %v", again, err)
	}
}
