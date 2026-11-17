package files

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/zachlatta/file-share/internal/blob"
)

// Before content addressing, every version was stored under its own random
// key (blobs/<uuid>). MigrateBlobs moves those objects to content keys one
// at a time, without downtime:
//
//  1. Read the legacy object and hash it. A hash that differs from the one
//     recorded at upload, or a missing object, is reported and skipped.
//  2. Under both keys' blob locks: copy it to blobs/sha256/<hex> unless that
//     content is already stored, re-read the copy and check its hash, then
//     repoint every version that used the legacy key, in one transaction.
//  3. Record the move in blob_migrations. The legacy object stays as a copy
//     until CleanupLegacyBlobs deletes it, or until nothing uses its content
//     any more: then Purge, PurgeFile or the sweep deletes it with the
//     content object.
//
// Readers resolve a version's key when they open it, and both the legacy and
// the content object hold the same bytes, so reads work throughout. Each
// object commits on its own, so an interrupted run loses nothing and the
// next run continues with the objects that are left.

// migrateBlobsLock keeps two migrations from running at once.
const migrateBlobsLock = 7316843922

type MigrateBlobsOptions struct {
	// DryRun only reads: it reports what a run would do.
	DryRun bool
	// Verify, in a dry run, also reads every legacy object and checks its
	// hash. A real run always does.
	Verify bool
	// Limit stops a real run after migrating this many objects (0: no
	// limit). Missing and mismatched objects do not count.
	Limit int
	// Progress, if set, receives one line per object.
	Progress func(string)
}

type MigrateBlobsReport struct {
	DryRun bool `json:"dry_run"`
	// LegacyObjects and LegacyBytes count the objects at legacy keys that
	// versions referenced when the run started.
	LegacyObjects int   `json:"legacy_objects"`
	LegacyBytes   int64 `json:"legacy_bytes"`
	// DistinctContents counts the distinct SHA-256 hashes among them.
	DistinctContents int `json:"distinct_contents"`
	// CopyBytes is what migrating all of them adds to the store: contents
	// not already stored at a content key, once each.
	CopyBytes int64 `json:"copy_bytes"`
	// SavedBytes is LegacyBytes - CopyBytes: the net reduction once
	// cleanup-legacy-blobs has removed the legacy objects.
	SavedBytes int64 `json:"saved_bytes"`
	// Migrated objects were repointed; Copied of them were copied to a new
	// content key and Reused found their content already stored.
	Migrated int `json:"migrated"`
	Copied   int `json:"copied"`
	Reused   int `json:"reused"`
	// Missing objects are gone from the store; Mismatched objects' bytes
	// do not match the recorded size or hash. Both are left untouched.
	Missing    []string `json:"missing,omitempty"`
	Mismatched []string `json:"mismatched,omitempty"`
	// Remaining objects are still at legacy keys after this run.
	Remaining int `json:"remaining"`
}

type legacyBlob struct {
	key    string
	sha256 string
	size   int64
	// consistent is false if versions sharing the key disagree on its
	// hash or size.
	consistent bool
}

func (s *Service) legacyBlobs(ctx context.Context) ([]legacyBlob, error) {
	rows, err := s.db.Query(ctx, `SELECT blob_key, min(sha256), min(size), min(sha256) = max(sha256) AND min(size) = max(size)
		FROM versions WHERE blob_key NOT LIKE 'blobs/sha256/%' GROUP BY blob_key ORDER BY blob_key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (legacyBlob, error) {
		var b legacyBlob
		err := row.Scan(&b.key, &b.sha256, &b.size, &b.consistent)
		return b, err
	})
}

// MigrateBlobs moves objects at legacy random keys to content keys. See the
// comment above for how it stays safe while the server runs.
func (s *Service) MigrateBlobs(ctx context.Context, opts MigrateBlobsOptions) (MigrateBlobsReport, error) {
	rep := MigrateBlobsReport{DryRun: opts.DryRun}
	if s.readOnly && !opts.DryRun {
		return rep, errors.New("migrate-blobs: a real run needs a writable service; use a dry run")
	}
	progress := opts.Progress
	if progress == nil {
		progress = func(string) {}
	}
	if !opts.DryRun {
		conn, err := s.db.Acquire(ctx)
		if err != nil {
			return rep, err
		}
		defer conn.Release()
		var locked bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, migrateBlobsLock).Scan(&locked); err != nil {
			return rep, err
		}
		if !locked {
			return rep, errors.New("migrate-blobs: another migration is running")
		}
		defer func() {
			_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrateBlobsLock)
		}()
	}

	legacy, err := s.legacyBlobs(ctx)
	if err != nil {
		return rep, err
	}
	stored := map[string]bool{}
	for _, b := range legacy {
		rep.LegacyObjects++
		rep.LegacyBytes += b.size
		if _, seen := stored[b.sha256]; seen {
			continue
		}
		rep.DistinctContents++
		_, err := s.blobs.Stat(ctx, contentKey(b.sha256))
		switch {
		case err == nil:
			stored[b.sha256] = true
		case errors.Is(err, blob.ErrNotFound):
			stored[b.sha256] = false
			rep.CopyBytes += b.size
		default:
			return rep, err
		}
	}
	rep.SavedBytes = rep.LegacyBytes - rep.CopyBytes
	rep.Remaining = rep.LegacyObjects

	for _, b := range legacy {
		if !opts.DryRun && opts.Limit > 0 && rep.Migrated >= opts.Limit {
			break
		}
		problem, err := s.checkLegacyBlob(ctx, b, opts.DryRun && !opts.Verify)
		if err != nil {
			return rep, err
		}
		switch problem {
		case "missing":
			rep.Missing = append(rep.Missing, b.key)
			progress(fmt.Sprintf("missing %s: the object is gone; left as is", b.key))
			continue
		case "mismatched":
			rep.Mismatched = append(rep.Mismatched, b.key)
			progress(fmt.Sprintf("mismatched %s: bytes do not match the recorded size or SHA-256; left as is", b.key))
			continue
		}
		if opts.DryRun {
			continue
		}
		copied, err := s.migrateBlob(ctx, b)
		if err != nil {
			return rep, fmt.Errorf("migrate %s: %w", b.key, err)
		}
		rep.Migrated++
		rep.Remaining--
		how := "reused existing content"
		if copied {
			rep.Copied++
			how = "copied"
		} else {
			rep.Reused++
		}
		progress(fmt.Sprintf("migrated %s -> %s (%d bytes, %s)", b.key, contentKey(b.sha256), b.size, how))
	}
	return rep, nil
}

// checkLegacyBlob returns "missing" or "mismatched" for an object that must
// not be migrated, or "" if it may be. With statOnly it does not read the
// bytes.
func (s *Service) checkLegacyBlob(ctx context.Context, b legacyBlob, statOnly bool) (string, error) {
	if !b.consistent {
		return "mismatched", nil
	}
	info, err := s.blobs.Stat(ctx, b.key)
	if errors.Is(err, blob.ErrNotFound) {
		return "missing", nil
	}
	if err != nil {
		return "", err
	}
	if info.Size != b.size {
		return "mismatched", nil
	}
	if statOnly {
		return "", nil
	}
	sum, err := s.hashObject(ctx, b.key)
	if errors.Is(err, blob.ErrNotFound) {
		return "missing", nil
	}
	if err != nil {
		return "", err
	}
	if sum != b.sha256 {
		return "mismatched", nil
	}
	return "", nil
}

// migrateBlob moves one verified legacy object to its content key and
// reports whether it had to copy the bytes.
func (s *Service) migrateBlob(ctx context.Context, b legacyBlob) (bool, error) {
	key := contentKey(b.sha256)
	copied := false
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		copied = false
		if err := lockBlob(ctx, tx, b.key); err != nil {
			return err
		}
		if err := lockBlob(ctx, tx, key); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO blobs (key, sha256, size, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT (key) DO NOTHING`,
			key, b.sha256, b.size, s.nowUTC()); err != nil {
			return err
		}
		info, err := s.blobs.Stat(ctx, key)
		switch {
		case err == nil:
			if info.Size != b.size {
				return fmt.Errorf("stored blob %s is %d bytes, not %d", key, info.Size, b.size)
			}
		case errors.Is(err, blob.ErrNotFound):
			if err := s.blobs.Copy(ctx, b.key, key); err != nil {
				return fmt.Errorf("copy: %w", err)
			}
			copied = true
			sum, err := s.hashObject(ctx, key)
			if err != nil || sum != b.sha256 {
				// Never leave wrong bytes under a content key. Nothing
				// references it, and its lock is held.
				_ = s.blobs.Delete(context.WithoutCancel(ctx), key)
				if err == nil {
					err = fmt.Errorf("copy has SHA-256 %s, not %s", sum, b.sha256)
				}
				return fmt.Errorf("verify copy: %w", err)
			}
		default:
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE versions SET blob_key = $2 WHERE blob_key = $1`, b.key, key); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO blob_migrations (old_key, new_key, sha256, size, migrated_at) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (old_key) DO UPDATE SET new_key = EXCLUDED.new_key, migrated_at = EXCLUDED.migrated_at, cleaned_at = NULL`,
			b.key, key, b.sha256, b.size, s.nowUTC()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM blobs WHERE key = $1`, b.key)
		return err
	})
	return copied, err
}

func (s *Service) hashObject(ctx context.Context, key string) (string, error) {
	obj, err := s.blobs.Get(ctx, key)
	if err != nil {
		return "", err
	}
	defer obj.Close()
	h := sha256.New()
	if _, err := io.Copy(h, obj); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type CleanupLegacyReport struct {
	Confirm bool `json:"confirm"`
	// Pending legacy objects are migrated and not yet deleted.
	Pending      int   `json:"pending"`
	PendingBytes int64 `json:"pending_bytes"`
	Deleted      int   `json:"deleted"`
	DeletedBytes int64 `json:"deleted_bytes"`
	// Skipped objects are still referenced, or their content is in use and
	// its copy does not verify; they are kept.
	Skipped []string `json:"skipped,omitempty"`
}

// CleanupLegacyBlobs deletes legacy objects that MigrateBlobs has moved, once
// nothing references them and either their content copy is in place or
// nothing uses that content either. Without confirm it only reports what it
// would delete.
func (s *Service) CleanupLegacyBlobs(ctx context.Context, confirm bool) (CleanupLegacyReport, error) {
	rep := CleanupLegacyReport{Confirm: confirm}
	rows, err := s.db.Query(ctx, `SELECT old_key, new_key, size FROM blob_migrations WHERE cleaned_at IS NULL ORDER BY old_key`)
	if err != nil {
		return rep, err
	}
	type pending struct {
		old, new string
		size     int64
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (pending, error) {
		var p pending
		err := row.Scan(&p.old, &p.new, &p.size)
		return p, err
	})
	if err != nil {
		return rep, err
	}
	for _, p := range items {
		rep.Pending++
		rep.PendingBytes += p.size
		if !confirm {
			continue
		}
		err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
			if err := lockBlob(ctx, tx, p.old); err != nil {
				return err
			}
			var used, contentUsed bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM versions WHERE blob_key = $1), EXISTS (SELECT 1 FROM versions WHERE blob_key = $2)`,
				p.old, p.new).Scan(&used, &contentUsed); err != nil {
				return err
			}
			if used {
				rep.Skipped = append(rep.Skipped, p.old)
				return nil
			}
			if contentUsed {
				info, err := s.blobs.Stat(ctx, p.new)
				if err != nil || info.Size != p.size {
					rep.Skipped = append(rep.Skipped, p.old)
					return nil
				}
			}
			if _, err := tx.Exec(ctx, `DELETE FROM blobs WHERE key = $1`, p.old); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE blob_migrations SET cleaned_at = $2 WHERE old_key = $1`, p.old, s.nowUTC()); err != nil {
				return err
			}
			if err := s.blobs.Delete(ctx, p.old); err != nil {
				return fmt.Errorf("delete %s: %w", p.old, err)
			}
			rep.Deleted++
			rep.DeletedBytes += p.size
			return nil
		})
		if err != nil {
			return rep, err
		}
	}
	return rep, nil
}
