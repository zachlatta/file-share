package files

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zachlatta/file-share/internal/blob"
)

const fileColumns = `f.id::text, f.namespace::text, f.name, COALESCE(f.password_hash, ''), f.current_version,
	f.created_at, f.updated_at, f.deleted_at, v.size, v.content_type, v.sha256`

const fileFrom = ` FROM files f JOIN versions v ON v.file_id = f.id AND v.number = f.current_version`

func (s *Service) scanFile(row pgx.Row) (File, error) {
	var f File
	err := row.Scan(&f.ID, &f.Namespace, &f.Name, &f.passwordHash, &f.Version,
		&f.CreatedAt, &f.UpdatedAt, &f.DeletedAt, &f.Size, &f.ContentType, &f.SHA256)
	if err != nil {
		return File{}, notFound(err)
	}
	s.decorate(&f)
	return f, nil
}

func (s *Service) decorate(f *File) {
	f.CreatedAt = f.CreatedAt.UTC()
	f.UpdatedAt = f.UpdatedAt.UTC()
	f.URL = s.URLFor(f.Namespace, f.Name)
	f.HasPassword = f.passwordHash != ""
	if f.HasPassword {
		sum := sha256.Sum256([]byte(f.passwordHash))
		f.PasswordStamp = hex.EncodeToString(sum[:8])
	}
	if f.DeletedAt != nil {
		deleted := f.DeletedAt.UTC()
		purge := deleted.Add(s.retention)
		f.DeletedAt, f.PurgeAt = &deleted, &purge
	}
}

// Get returns a file by ID, live or deleted.
func (s *Service) Get(ctx context.Context, id string) (File, error) {
	if _, err := uuid.Parse(id); err != nil {
		return File{}, fmt.Errorf("%w: file ID must be a UUID", ErrNotFound)
	}
	return s.scanFile(s.db.QueryRow(ctx, `SELECT `+fileColumns+fileFrom+` WHERE f.id = $1`, id))
}

// Lookup returns the live file at a public path.
func (s *Service) Lookup(ctx context.Context, namespace, name string) (File, error) {
	if _, err := uuid.Parse(namespace); err != nil {
		return File{}, ErrNotFound
	}
	return s.scanFile(s.db.QueryRow(ctx, `SELECT `+fileColumns+fileFrom+` WHERE f.namespace = $1 AND f.name = $2 AND f.deleted_at IS NULL`, namespace, name))
}

// Resolve finds a file from a reference an agent is likely to have: a file
// ID, a public URL, or "namespace/name". IDs match deleted files too.
func (s *Service) Resolve(ctx context.Context, ref string) (File, error) {
	ref = strings.TrimSpace(ref)
	if _, err := uuid.Parse(ref); err == nil {
		return s.Get(ctx, ref)
	}
	p := ref
	if u, err := url.Parse(ref); err == nil && u.Scheme != "" && u.Host != "" {
		p = u.Path
	}
	if unescaped, err := url.PathUnescape(p); err == nil {
		p = unescaped
	}
	ns, name, ok := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	if !ok {
		return File{}, fmt.Errorf("%w: %q is not a file ID, URL, or namespace/name", ErrNotFound, ref)
	}
	return s.Lookup(ctx, ns, name)
}

type ListOptions struct {
	Namespace string
	// Deleted lists only deleted (restorable) files instead of live ones.
	Deleted bool
	// Query matches a case-insensitive substring of the name.
	Query  string
	Limit  int
	Offset int
}

// List returns files, most recently updated first.
func (s *Service) List(ctx context.Context, opts ListOptions) ([]File, error) {
	if opts.Limit <= 0 || opts.Limit > 1000 {
		opts.Limit = 100
	}
	where := []string{"f.deleted_at IS NULL"}
	if opts.Deleted {
		where[0] = "f.deleted_at IS NOT NULL"
	}
	args := []any{}
	if opts.Namespace != "" {
		if _, err := uuid.Parse(opts.Namespace); err != nil {
			return nil, fmt.Errorf("%w: namespace must be a UUID", ErrInvalid)
		}
		args = append(args, opts.Namespace)
		where = append(where, fmt.Sprintf("f.namespace = $%d", len(args)))
	}
	if opts.Query != "" {
		args = append(args, "%"+strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(opts.Query)+"%")
		where = append(where, fmt.Sprintf("f.name ILIKE $%d", len(args)))
	}
	args = append(args, opts.Limit, opts.Offset)
	query := `SELECT ` + fileColumns + fileFrom + ` WHERE ` + strings.Join(where, " AND ") +
		fmt.Sprintf(` ORDER BY f.updated_at DESC, f.id LIMIT $%d OFFSET $%d`, len(args)-1, len(args))
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		f, err := s.scanFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Versions lists a file's retained versions, newest first.
func (s *Service) Versions(ctx context.Context, id string) ([]Version, error) {
	f, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT number, blob_key, size, content_type, sha256, created_at, COALESCE(created_by, ''), COALESCE(note, ''), superseded_at
		FROM versions WHERE file_id = $1 ORDER BY number DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		s.decorateVersion(&v, f)
		out = append(out, v)
	}
	return out, rows.Err()
}

func scanVersion(row pgx.Row) (Version, error) {
	var v Version
	err := row.Scan(&v.Number, &v.blobKey, &v.Size, &v.ContentType, &v.SHA256, &v.CreatedAt, &v.CreatedBy, &v.Note, &v.SupersededAt)
	return v, err
}

func (s *Service) decorateVersion(v *Version, f File) {
	v.CreatedAt = v.CreatedAt.UTC()
	v.Current = v.Number == f.Version
	if v.SupersededAt != nil && !v.Current {
		at := v.SupersededAt.UTC()
		purge := at.Add(s.retention)
		v.SupersededAt, v.PurgeAt = &at, &purge
	}
	if f.PurgeAt != nil && (v.PurgeAt == nil || f.PurgeAt.Before(*v.PurgeAt)) {
		v.PurgeAt = f.PurgeAt
	}
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *Service) version(ctx context.Context, q querier, id string, number int) (Version, error) {
	v, err := scanVersion(q.QueryRow(ctx, `SELECT number, blob_key, size, content_type, sha256, created_at, COALESCE(created_by, ''), COALESCE(note, ''), superseded_at
		FROM versions WHERE file_id = $1 AND number = $2`, id, number))
	if err != nil {
		return Version{}, fmt.Errorf("%w: version %d", notFound(err), number)
	}
	return v, nil
}

// Open returns the bytes of a version (0 = current) of a file.
func (s *Service) Open(ctx context.Context, id string, number int) (blob.Object, Version, error) {
	f, err := s.Get(ctx, id)
	if err != nil {
		return nil, Version{}, err
	}
	if number <= 0 {
		number = f.Version
	}
	v, err := s.version(ctx, s.db, f.ID, number)
	if err != nil {
		return nil, Version{}, err
	}
	s.decorateVersion(&v, f)
	obj, err := s.blobs.Get(ctx, v.blobKey)
	if err != nil {
		return nil, Version{}, fmt.Errorf("read bytes: %w", err)
	}
	return obj, v, nil
}

type Stats struct {
	Files        int   `json:"files"`
	Bytes        int64 `json:"bytes"`
	DeletedFiles int   `json:"deleted_files"`
	// StoredBytes counts every retained version, deleted files included.
	StoredBytes int64 `json:"stored_bytes"`
	Namespaces  int   `json:"namespaces"`
}

func (s *Service) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	err := s.db.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE f.deleted_at IS NULL),
		COALESCE(sum(v.size) FILTER (WHERE f.deleted_at IS NULL), 0),
		count(*) FILTER (WHERE f.deleted_at IS NOT NULL),
		count(DISTINCT f.namespace) FILTER (WHERE f.deleted_at IS NULL)`+fileFrom).Scan(&st.Files, &st.Bytes, &st.DeletedFiles, &st.Namespaces)
	if err != nil {
		return st, err
	}
	err = s.db.QueryRow(ctx, `SELECT COALESCE(sum(size), 0) FROM (SELECT DISTINCT ON (blob_key) blob_key, size FROM versions) b`).Scan(&st.StoredBytes)
	return st, err
}

// CleanName validates a file name. Names may contain "/" to form folders
// inside a namespace, but no empty, "." or ".." segments.
func CleanName(name string) (string, error) {
	invalid := func(why string) (string, error) {
		return "", fmt.Errorf("%w: file name %s", ErrInvalid, why)
	}
	if name == "" {
		return invalid("is required")
	}
	if len(name) > 255 {
		return invalid("must be at most 255 bytes")
	}
	if !utf8.ValidString(name) {
		return invalid("must be valid UTF-8")
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '\\' {
			return invalid("must not contain control characters or backslashes")
		}
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return invalid("must not have empty, '.' or '..' path segments")
		}
	}
	return name, nil
}

var extensionTypes = map[string]string{
	".txt": "text/plain; charset=utf-8", ".md": "text/markdown; charset=utf-8", ".csv": "text/csv; charset=utf-8",
	".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
	".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".json": "application/json",
	".xml": "application/xml", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
	".gif": "image/gif", ".webp": "image/webp", ".avif": "image/avif", ".heic": "image/heic", ".ico": "image/x-icon",
	".pdf": "application/pdf", ".zip": "application/zip", ".gz": "application/gzip", ".tar": "application/x-tar",
	".mp4": "video/mp4", ".mov": "video/quicktime", ".webm": "video/webm", ".mp3": "audio/mpeg", ".m4a": "audio/mp4",
	".wav": "audio/wav", ".ogg": "audio/ogg", ".wasm": "application/wasm", ".woff2": "font/woff2", ".woff": "font/woff",
	".ttf": "font/ttf", ".otf": "font/otf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".yaml": "text/yaml; charset=utf-8", ".yml": "text/yaml; charset=utf-8", ".go": "text/plain; charset=utf-8",
	".py": "text/plain; charset=utf-8", ".sh": "text/plain; charset=utf-8", ".log": "text/plain; charset=utf-8",
}

// DetectContentType picks a MIME type from the extension, falling back to
// sniffing the first bytes.
func DetectContentType(name string, head []byte) string {
	ext := strings.ToLower(path.Ext(name))
	if t, ok := extensionTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return http.DetectContentType(head)
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "22P02" { // invalid_text_representation (bad UUID)
		return ErrNotFound
	}
	return err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
