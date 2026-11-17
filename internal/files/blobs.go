package files

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zachlatta/file-share/internal/blob"
)

// Content-addressed storage.
//
// An upload streams its bytes to a unique staging key while hashing them,
// then attaches the content key blobs/sha256/<hex> inside the transaction
// that inserts its version: if an object with that hash is already stored the
// staged copy is simply dropped, otherwise it is copied server-side to the
// content key. S3 has no rename, and the hash is only known once the bytes
// have been read, so staging then copying is the only way to write each
// content key exactly once without buffering whole files on local disk.
//
// Each versions row is a reference ("lock") on its blob, and a blob is
// deleted only once no versions row references it. Files with the same bytes
// and different expiries therefore share one object until the last of them
// is purged.
//
// Races between an upload reusing a blob and a purge deleting it are
// settled by a per-key transaction-scoped advisory lock. Attaching a blob
// (upload, replace, rollback, migrate-blobs) and deleting one (Purge,
// PurgeFile, the orphan sweep) both take it, and an attach holds it until the
// transaction that inserts the referencing version commits. So a delete
// either sees the new reference and keeps the blob, or finishes first and the
// upload stores the bytes again from its staged copy. The foreign key from
// versions to blobs backs this up in the database.
const (
	contentPrefix = "blobs/sha256/"
	stagingPrefix = "staging/"
)

// orphanGrace protects objects that are written outside a blob lock: staged
// uploads waiting to attach. An object is listed only once its write has
// finished, so an upload would have to stall this long to be at risk.
// Unreferenced blobs get the same grace before the sweep deletes them.
const orphanGrace = 24 * time.Hour

func contentKey(sum string) string { return contentPrefix + sum }

// lockBlob takes key's blob lock until tx ends.
func lockBlob(ctx context.Context, tx pgx.Tx, key string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)
	return err
}

// attachBlob makes sure v's blob is recorded and stored, under its lock in
// tx, so the caller can insert a version that references it before the lock
// is released. If the bytes are missing it copies them from staging; with
// no staging copy that is an error.
func (s *Service) attachBlob(ctx context.Context, tx pgx.Tx, v Version, staging string) error {
	if err := lockBlob(ctx, tx, v.blobKey); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO blobs (key, sha256, size, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT (key) DO NOTHING`,
		v.blobKey, v.SHA256, v.Size, s.nowUTC()); err != nil {
		return err
	}
	info, err := s.blobs.Stat(ctx, v.blobKey)
	switch {
	case err == nil:
		if info.Size != v.Size {
			return fmt.Errorf("stored blob %s is %d bytes, not %d", v.blobKey, info.Size, v.Size)
		}
		return nil
	case !errors.Is(err, blob.ErrNotFound):
		return fmt.Errorf("check stored bytes: %w", err)
	case staging == "":
		return fmt.Errorf("%w: the bytes of this version are missing", ErrNotFound)
	}
	if err := s.blobs.Copy(ctx, staging, v.blobKey); err != nil {
		return fmt.Errorf("store bytes: %w", err)
	}
	if info, err := s.blobs.Stat(ctx, v.blobKey); err != nil || info.Size != v.Size {
		return fmt.Errorf("store bytes: copy of %s did not verify (%d bytes, %v)", v.blobKey, info.Size, err)
	}
	return nil
}

// dropStaging deletes a staged upload. A failure is left to the sweep.
func (s *Service) dropStaging(ctx context.Context, staging string) {
	_ = s.blobs.Delete(context.WithoutCancel(ctx), staging)
}

// releaseBlob deletes key after a failed upload if nothing else uses it.
func (s *Service) releaseBlob(ctx context.Context, key string) {
	_, _ = s.deleteBlobIfUnused(context.WithoutCancel(ctx), key)
}

// deleteBlobIfUnused deletes key's object and row, under its lock, unless a
// version references it or it is a migrated legacy object awaiting
// cleanup-legacy-blobs. If the object delete fails, the row stays for the
// sweep to retry.
func (s *Service) deleteBlobIfUnused(ctx context.Context, key string) (bool, error) {
	deleted := false
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := lockBlob(ctx, tx, key); err != nil {
			return err
		}
		var keep bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM versions WHERE blob_key = $1)
			OR EXISTS (SELECT 1 FROM blob_migrations WHERE old_key = $1 AND cleaned_at IS NULL)`, key).Scan(&keep); err != nil {
			return err
		}
		if keep {
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM blobs WHERE key = $1`, key); err != nil {
			return err
		}
		if err := s.blobs.Delete(ctx, key); err != nil {
			return fmt.Errorf("delete blob %s: %w", key, err)
		}
		deleted = true
		return nil
	})
	return deleted, err
}

// deleteUnusedBlobs deletes each of keys that nothing uses any more and
// returns how many it deleted.
func (s *Service) deleteUnusedBlobs(ctx context.Context, keys []string) (int, error) {
	seen := map[string]bool{}
	var errs []error
	deleted := 0
	for _, key := range keys {
		if seen[key] {
			continue
		}
		seen[key] = true
		ok, err := s.deleteBlobIfUnused(ctx, key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ok {
			deleted++
		}
	}
	return deleted, errors.Join(errs...)
}

// purgeOrphans deletes, once they are older than orphanGrace: objects under
// blobs/ and rows in blobs that no version references (bytes left when a
// delete or a failed upload's cleanup failed), and staged uploads (left when
// the server stopped mid-upload). Migrated legacy objects are kept for
// cleanup-legacy-blobs.
func (s *Service) purgeOrphans(ctx context.Context) (int, error) {
	cutoff := s.now().Add(-orphanGrace)
	var errs []error
	deleted := 0

	staged, err := s.blobs.List(ctx, stagingPrefix)
	if err != nil {
		errs = append(errs, err)
	}
	for _, obj := range staged {
		if !obj.Modified.Before(cutoff) {
			continue
		}
		if err := s.blobs.Delete(ctx, obj.Key); err != nil {
			errs = append(errs, fmt.Errorf("delete staged upload %s: %w", obj.Key, err))
			continue
		}
		deleted++
	}

	candidates, err := s.blobKeys(ctx, `SELECT key FROM blobs b WHERE created_at < $1
		AND NOT EXISTS (SELECT 1 FROM versions WHERE blob_key = b.key)
		AND NOT EXISTS (SELECT 1 FROM blob_migrations WHERE old_key = b.key AND cleaned_at IS NULL)`, cutoff)
	if err != nil {
		errs = append(errs, err)
	}
	objects, err := s.blobs.List(ctx, "blobs/")
	if err != nil {
		errs = append(errs, err)
	}
	var old []string
	for _, obj := range objects {
		if obj.Modified.Before(cutoff) && !slices.Contains(candidates, obj.Key) {
			old = append(old, obj.Key)
		}
	}
	for batch := range slices.Chunk(old, 1000) {
		used, err := s.blobKeys(ctx, `SELECT blob_key FROM versions WHERE blob_key = ANY($1)
			UNION SELECT old_key FROM blob_migrations WHERE old_key = ANY($1) AND cleaned_at IS NULL`, batch)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, key := range batch {
			if !slices.Contains(used, key) {
				candidates = append(candidates, key)
			}
		}
	}
	n, err := s.deleteUnusedBlobs(ctx, candidates)
	return deleted + n, errors.Join(append(errs, err)...)
}

func isContentKey(key string) bool { return strings.HasPrefix(key, contentPrefix) }
