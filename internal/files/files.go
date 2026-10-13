// Package files is the file-sharing domain: namespaces, files, immutable
// versions, soft deletion with a retention window, and passwords.
//
// Metadata lives in PostgreSQL; bytes live in a blob.Store under random keys
// that are written once and never modified. Replacing a file adds a version;
// rolling back adds a version that reuses an older version's blob; deleting a
// file only marks it deleted. Purge permanently removes deleted files and
// non-current versions once they are older than the retention window, and
// deletes a blob only when no remaining version references it.
package files

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zachlatta/file-share/internal/blob"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("a live file with that name already exists in the namespace")
	ErrInvalid  = errors.New("invalid input")
	ErrTooLarge = errors.New("file is larger than the upload limit")
)

type Config struct {
	DatabaseURL string
	Blobs       blob.Store
	// BaseURL is the public origin used to build file URLs.
	BaseURL string
	// Retention is how long deleted files and replaced versions are kept.
	Retention time.Duration
	// MaxBytes caps a single upload. Zero means no limit.
	MaxBytes int64
	Now      func() time.Time
}

type Service struct {
	db        *pgxpool.Pool
	blobs     blob.Store
	baseURL   string
	retention time.Duration
	maxBytes  int64
	now       func() time.Time
}

// File is a file's current state. Times are UTC.
type File struct {
	ID          string     `json:"id"`
	Namespace   string     `json:"namespace"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	Size        int64      `json:"size"`
	ContentType string     `json:"content_type"`
	SHA256      string     `json:"sha256"`
	Version     int        `json:"version"`
	HasPassword bool       `json:"has_password"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
	// PurgeAt is when a deleted file will be permanently removed.
	PurgeAt *time.Time `json:"purge_at,omitempty"`

	// PasswordStamp changes whenever the password changes, so access
	// cookies can be bound to the current password.
	PasswordStamp string `json:"-"`
	passwordHash  string
}

type Version struct {
	Number       int        `json:"number"`
	Current      bool       `json:"current"`
	Size         int64      `json:"size"`
	ContentType  string     `json:"content_type"`
	SHA256       string     `json:"sha256"`
	CreatedAt    time.Time  `json:"created_at"`
	CreatedBy    string     `json:"created_by,omitempty"`
	Note         string     `json:"note,omitempty"`
	SupersededAt *time.Time `json:"superseded_at,omitempty"`
	// PurgeAt is when a non-current version will be permanently removed.
	PurgeAt *time.Time `json:"purge_at,omitempty"`
	blobKey string
}

func Open(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Blobs == nil {
		return nil, errors.New("files: blob store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 30 * 24 * time.Hour
	}
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Service{
		db: pool, blobs: cfg.Blobs, baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		retention: cfg.Retention, maxBytes: cfg.MaxBytes, now: cfg.Now,
	}, nil
}

func (s *Service) Close() { s.db.Close() }

func (s *Service) Retention() time.Duration { return s.retention }
func (s *Service) MaxBytes() int64          { return s.maxBytes }
func (s *Service) BaseURL() string          { return s.baseURL }

// Ping checks the database and the blob store.
func (s *Service) Ping(ctx context.Context) error {
	if err := s.db.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	if err := s.blobs.Ping(ctx); err != nil {
		return fmt.Errorf("object store: %w", err)
	}
	return nil
}

func (s *Service) nowUTC() time.Time { return s.now().UTC().Truncate(time.Microsecond) }

// URLFor builds the public URL for a file path.
func (s *Service) URLFor(namespace, name string) string {
	segments := strings.Split(name, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	return s.baseURL + "/" + namespace + "/" + strings.Join(segments, "/")
}

type UploadInput struct {
	// Namespace is an existing namespace UUID, or empty for a new one.
	Namespace   string
	Name        string
	ContentType string
	Body        io.Reader
	// Size is the body length, or -1 if unknown.
	Size     int64
	Password string
	Client   string
}

func (s *Service) Upload(ctx context.Context, in UploadInput) (File, error) {
	name, err := CleanName(in.Name)
	if err != nil {
		return File{}, err
	}
	ns := in.Namespace
	if ns == "" {
		ns = uuid.NewString()
	} else if parsed, err := uuid.Parse(ns); err != nil {
		return File{}, fmt.Errorf("%w: namespace must be a UUID", ErrInvalid)
	} else {
		ns = parsed.String()
	}
	var hash string
	if in.Password != "" {
		if hash, err = hashPassword(in.Password); err != nil {
			return File{}, err
		}
	}
	if _, err := s.Lookup(ctx, ns, name); err == nil {
		return File{}, ErrExists
	} else if !errors.Is(err, ErrNotFound) {
		return File{}, err
	}
	v, err := s.storeBlob(ctx, name, in.ContentType, in.Body, in.Size)
	if err != nil {
		return File{}, err
	}
	now := s.nowUTC()
	id := uuid.NewString()
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO files (id, namespace, name, password_hash, current_version, created_at, updated_at)
			VALUES ($1, $2, $3, NULLIF($4, ''), 1, $5, $5)`, id, ns, name, hash, now); err != nil {
			return err
		}
		return insertVersion(ctx, tx, id, 1, v, now, in.Client, "")
	})
	if err != nil {
		_ = s.blobs.Delete(context.WithoutCancel(ctx), v.blobKey)
		if isUniqueViolation(err) {
			return File{}, ErrExists
		}
		return File{}, err
	}
	return s.Get(ctx, id)
}

type ReplaceInput struct {
	ContentType string
	Body        io.Reader
	Size        int64
	Client      string
	Note        string
}

// Replace uploads new content for a live file as a new version. The URL,
// password and older versions are kept.
func (s *Service) Replace(ctx context.Context, id string, in ReplaceInput) (File, error) {
	f, err := s.Get(ctx, id)
	if err != nil {
		return File{}, err
	}
	if f.DeletedAt != nil {
		return File{}, fmt.Errorf("%w: file is deleted; restore it first", ErrNotFound)
	}
	v, err := s.storeBlob(ctx, f.Name, in.ContentType, in.Body, in.Size)
	if err != nil {
		return File{}, err
	}
	if err := s.addVersion(ctx, f.ID, v, in.Client, in.Note); err != nil {
		_ = s.blobs.Delete(context.WithoutCancel(ctx), v.blobKey)
		return File{}, err
	}
	return s.Get(ctx, f.ID)
}

// Rollback makes an older version current again by adding a new version
// that shares its bytes.
func (s *Service) Rollback(ctx context.Context, id string, number int, client string) (File, error) {
	f, err := s.Get(ctx, id)
	if err != nil {
		return File{}, err
	}
	if f.DeletedAt != nil {
		return File{}, fmt.Errorf("%w: file is deleted; restore it first", ErrNotFound)
	}
	old, err := s.version(ctx, s.db, f.ID, number)
	if err != nil {
		return File{}, err
	}
	if err := s.addVersion(ctx, f.ID, old, client, fmt.Sprintf("rollback to v%d", number)); err != nil {
		return File{}, err
	}
	return s.Get(ctx, f.ID)
}

func (s *Service) addVersion(ctx context.Context, id string, v Version, client, note string) error {
	now := s.nowUTC()
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var current int
		var deleted *time.Time
		if err := tx.QueryRow(ctx, `SELECT current_version, deleted_at FROM files WHERE id = $1 FOR UPDATE`, id).Scan(&current, &deleted); err != nil {
			return notFound(err)
		}
		if deleted != nil {
			return fmt.Errorf("%w: file is deleted", ErrNotFound)
		}
		if _, err := tx.Exec(ctx, `UPDATE versions SET superseded_at = $3 WHERE file_id = $1 AND number = $2`, id, current, now); err != nil {
			return err
		}
		if err := insertVersion(ctx, tx, id, current+1, v, now, client, note); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE files SET current_version = $2, updated_at = $3 WHERE id = $1`, id, current+1, now)
		return err
	})
}

func insertVersion(ctx context.Context, tx pgx.Tx, id string, number int, v Version, now time.Time, client, note string) error {
	_, err := tx.Exec(ctx, `INSERT INTO versions (file_id, number, blob_key, size, content_type, sha256, created_at, created_by, note)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''))`,
		id, number, v.blobKey, v.Size, v.ContentType, v.SHA256, now, client, note)
	return err
}

// storeBlob streams body into a new blob, computing size and SHA-256, and
// enforcing MaxBytes. The content type is taken from the caller, then the
// file extension, then content sniffing.
func (s *Service) storeBlob(ctx context.Context, name, contentType string, body io.Reader, size int64) (Version, error) {
	if body == nil {
		return Version{}, fmt.Errorf("%w: content is required", ErrInvalid)
	}
	if s.maxBytes > 0 && size > s.maxBytes {
		return Version{}, ErrTooLarge
	}
	buffered := bufio.NewReaderSize(body, 512)
	head, err := buffered.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return Version{}, err
	}
	contentType = strings.TrimSpace(contentType)
	if contentType == "" || contentType == "application/octet-stream" {
		contentType = DetectContentType(name, head)
	}
	hasher := sha256.New()
	counter := &countingReader{r: buffered, limit: s.maxBytes}
	reader := io.TeeReader(counter, hasher)
	key := "blobs/" + uuid.NewString()
	if err := s.blobs.Put(ctx, key, reader, size, contentType); err != nil {
		_ = s.blobs.Delete(context.WithoutCancel(ctx), key)
		if counter.exceeded {
			return Version{}, ErrTooLarge
		}
		return Version{}, fmt.Errorf("store bytes: %w", err)
	}
	if counter.exceeded {
		_ = s.blobs.Delete(context.WithoutCancel(ctx), key)
		return Version{}, ErrTooLarge
	}
	return Version{blobKey: key, Size: counter.n, ContentType: contentType, SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

type countingReader struct {
	r        io.Reader
	n        int64
	limit    int64
	exceeded bool
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.limit > 0 && c.n > c.limit {
		c.exceeded = true
		return n, ErrTooLarge
	}
	return n, err
}

// Delete soft-deletes a live file. It stays restorable until PurgeAt.
func (s *Service) Delete(ctx context.Context, id string) (File, error) {
	tag, err := s.db.Exec(ctx, `UPDATE files SET deleted_at = $2, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL`, id, s.nowUTC())
	if err != nil {
		return File{}, notFound(err)
	}
	if tag.RowsAffected() == 0 {
		return File{}, fmt.Errorf("%w: no live file with that ID", ErrNotFound)
	}
	return s.Get(ctx, id)
}

// Restore undeletes a file at its original URL.
func (s *Service) Restore(ctx context.Context, id string) (File, error) {
	tag, err := s.db.Exec(ctx, `UPDATE files SET deleted_at = NULL, updated_at = $2 WHERE id = $1 AND deleted_at IS NOT NULL`, id, s.nowUTC())
	if err != nil {
		if isUniqueViolation(err) {
			return File{}, fmt.Errorf("%w: rename or delete the other file first", ErrExists)
		}
		return File{}, notFound(err)
	}
	if tag.RowsAffected() == 0 {
		return File{}, fmt.Errorf("%w: no deleted file with that ID", ErrNotFound)
	}
	return s.Get(ctx, id)
}

func (s *Service) Rename(ctx context.Context, id, newName string) (File, error) {
	name, err := CleanName(newName)
	if err != nil {
		return File{}, err
	}
	tag, err := s.db.Exec(ctx, `UPDATE files SET name = $2, updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`, id, name, s.nowUTC())
	if err != nil {
		if isUniqueViolation(err) {
			return File{}, ErrExists
		}
		return File{}, notFound(err)
	}
	if tag.RowsAffected() == 0 {
		return File{}, fmt.Errorf("%w: no live file with that ID", ErrNotFound)
	}
	return s.Get(ctx, id)
}

// SetPassword sets or (with "") clears a file's password.
func (s *Service) SetPassword(ctx context.Context, id, password string) (File, error) {
	var hash string
	if password != "" {
		var err error
		if hash, err = hashPassword(password); err != nil {
			return File{}, err
		}
	}
	tag, err := s.db.Exec(ctx, `UPDATE files SET password_hash = NULLIF($2, ''), updated_at = $3 WHERE id = $1`, id, hash, s.nowUTC())
	if err != nil {
		return File{}, notFound(err)
	}
	if tag.RowsAffected() == 0 {
		return File{}, ErrNotFound
	}
	return s.Get(ctx, id)
}

// CheckPassword reports whether password opens f. Files without a password
// are always open.
func (s *Service) CheckPassword(f File, password string) bool {
	if f.passwordHash == "" {
		return true
	}
	return password != "" && bcrypt.CompareHashAndPassword([]byte(f.passwordHash), []byte(password)) == nil
}

func hashPassword(password string) (string, error) {
	if len(password) > 72 {
		return "", fmt.Errorf("%w: password must be at most 72 bytes", ErrInvalid)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// PurgeFile permanently deletes a file and all of its versions immediately.
func (s *Service) PurgeFile(ctx context.Context, id string) error {
	keys, err := s.blobKeys(ctx, `SELECT DISTINCT blob_key FROM versions WHERE file_id = $1`, id)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM files WHERE id = $1`, id)
	if err != nil {
		return notFound(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = s.deleteOrphanBlobs(ctx, keys)
	return err
}

type PurgeResult struct {
	Files    int `json:"files"`
	Versions int `json:"versions"`
	Blobs    int `json:"blobs"`
	// Parts counts abandoned chunked-upload parts removed.
	Parts int `json:"parts"`
}

// Purge permanently removes deleted files and replaced versions that are
// older than the retention window.
func (s *Service) Purge(ctx context.Context) (PurgeResult, error) {
	var res PurgeResult
	cutoff := s.nowUTC().Add(-s.retention)
	var keys []string
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			DELETE FROM versions v USING files f
			WHERE v.file_id = f.id AND (
				(f.deleted_at IS NOT NULL AND f.deleted_at <= $1) OR
				(v.superseded_at IS NOT NULL AND v.superseded_at <= $1 AND v.number <> f.current_version))
			RETURNING v.blob_key`, cutoff)
		if err != nil {
			return err
		}
		keys, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		res.Versions = len(keys)
		tag, err := tx.Exec(ctx, `DELETE FROM files WHERE deleted_at IS NOT NULL AND deleted_at <= $1`, cutoff)
		res.Files = int(tag.RowsAffected())
		return err
	})
	if err != nil {
		return PurgeResult{}, err
	}
	var blobErr, partErr error
	res.Blobs, blobErr = s.deleteOrphanBlobs(ctx, keys)
	res.Parts, partErr = s.purgeParts(ctx)
	return res, errors.Join(blobErr, partErr)
}

func (s *Service) blobKeys(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// deleteOrphanBlobs deletes each blob no version references any more and
// returns how many it deleted.
func (s *Service) deleteOrphanBlobs(ctx context.Context, keys []string) (int, error) {
	seen := map[string]bool{}
	var errs []error
	deleted := 0
	for _, key := range keys {
		if seen[key] {
			continue
		}
		seen[key] = true
		var used bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM versions WHERE blob_key = $1)`, key).Scan(&used); err != nil {
			errs = append(errs, err)
			continue
		}
		if used {
			continue
		}
		if err := s.blobs.Delete(ctx, key); err != nil {
			errs = append(errs, fmt.Errorf("delete blob %s: %w", key, err))
			continue
		}
		deleted++
	}
	return deleted, errors.Join(errs...)
}
