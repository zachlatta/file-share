package files

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Upload links let an agent hand a URL to curl instead of holding the
// secret. Each link works once: it records where the file goes (a new file,
// or a new version of an existing one) and who can open it, and the request
// only supplies the bytes and, when the link has no name, the file name.

type UploadLinkInput struct {
	// Namespace is an existing namespace UUID, or empty for a new one. The
	// namespace is chosen when the link is made, so its URL is known early.
	Namespace string
	// Name is the file name, or empty to take it from the upload.
	Name string
	// FileID makes the link replace that file instead of creating one.
	FileID        string
	Password      string
	AllowedEmails []string
	Client        string
	ExpiresAt     time.Time
}

type UploadLink struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	FileID    string `json:"file_id,omitempty"`
	// URL is the file's public URL, or "" while the name is unknown.
	URL       string    `json:"url,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// LinkUpload is the request side of an upload through a link.
type LinkUpload struct {
	// Name is used only when the link has none.
	Name        string
	ContentType string
	Body        io.Reader
	Size        int64
}

func (s *Service) CreateUploadLink(ctx context.Context, in UploadLinkInput) (UploadLink, error) {
	if in.ExpiresAt.IsZero() {
		return UploadLink{}, fmt.Errorf("%w: upload link needs an expiry", ErrInvalid)
	}
	link := UploadLink{ID: uuid.NewString(), ExpiresAt: in.ExpiresAt.UTC().Truncate(time.Microsecond)}
	var hash string
	var emails []string
	if in.FileID != "" {
		if in.Name != "" || in.Namespace != "" || in.Password != "" || len(in.AllowedEmails) > 0 {
			return UploadLink{}, fmt.Errorf("%w: a replace link keeps the file's name, password and allowed emails; change those separately", ErrInvalid)
		}
		f, err := s.Get(ctx, in.FileID)
		if err != nil {
			return UploadLink{}, err
		}
		if f.DeletedAt != nil {
			return UploadLink{}, fmt.Errorf("%w: file is deleted; restore it first", ErrNotFound)
		}
		link.FileID, link.URL = f.ID, f.URL
	} else {
		if in.Name != "" {
			name, err := CleanName(in.Name)
			if err != nil {
				return UploadLink{}, err
			}
			link.Name = name
		}
		link.Namespace = uuid.NewString()
		if in.Namespace != "" {
			ns, err := uuid.Parse(in.Namespace)
			if err != nil {
				return UploadLink{}, fmt.Errorf("%w: namespace must be a UUID", ErrInvalid)
			}
			link.Namespace = ns.String()
		}
		var err error
		if emails, err = s.cleanEmails(in.AllowedEmails); err != nil {
			return UploadLink{}, err
		}
		if in.Password != "" {
			if hash, err = hashPassword(in.Password); err != nil {
				return UploadLink{}, err
			}
		}
		if link.Name != "" {
			if _, err := s.Lookup(ctx, link.Namespace, link.Name); err == nil {
				return UploadLink{}, ErrExists
			} else if !errors.Is(err, ErrNotFound) {
				return UploadLink{}, err
			}
			link.URL = s.URLFor(link.Namespace, link.Name)
		}
	}
	_, err := s.db.Exec(ctx, `INSERT INTO upload_links (id, namespace, name, file_id, password_hash, allowed_emails, client, created_at, expires_at)
		VALUES ($1, NULLIF($2, '')::uuid, $3, NULLIF($4, '')::uuid, NULLIF($5, ''), $6, $7, $8, $9)`,
		link.ID, link.Namespace, link.Name, link.FileID, hash, append([]string{}, emails...), in.Client, s.nowUTC(), link.ExpiresAt)
	if err != nil {
		return UploadLink{}, err
	}
	return link, nil
}

// UploadLink returns a link that can still be used: ErrNotFound if it does
// not exist or has expired, ErrLinkUsed if it has been used.
func (s *Service) UploadLink(ctx context.Context, id string) (UploadLink, error) {
	if _, err := uuid.Parse(id); err != nil {
		return UploadLink{}, fmt.Errorf("%w: upload link", ErrNotFound)
	}
	var link UploadLink
	var used *time.Time
	err := s.db.QueryRow(ctx, `SELECT id::text, COALESCE(namespace::text, ''), name, COALESCE(file_id::text, ''), expires_at, used_at
		FROM upload_links WHERE id = $1`, id).Scan(&link.ID, &link.Namespace, &link.Name, &link.FileID, &link.ExpiresAt, &used)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return UploadLink{}, fmt.Errorf("%w: upload link", ErrNotFound)
	case err != nil:
		return UploadLink{}, err
	case used != nil:
		return UploadLink{}, ErrLinkUsed
	case !link.ExpiresAt.After(s.nowUTC()):
		return UploadLink{}, fmt.Errorf("%w: upload link expired", ErrNotFound)
	}
	if link.Name != "" {
		link.URL = s.URLFor(link.Namespace, link.Name)
	}
	return link, nil
}

// UploadWithLink uses link id once. The link is claimed before the upload so
// two concurrent requests cannot both succeed, and released again if the
// upload fails so the caller can retry.
func (s *Service) UploadWithLink(ctx context.Context, id string, in LinkUpload) (File, error) {
	if _, err := uuid.Parse(id); err != nil {
		return File{}, fmt.Errorf("%w: upload link", ErrNotFound)
	}
	var ns, name, fileID, hash, client string
	var emails []string
	err := s.db.QueryRow(ctx, `UPDATE upload_links SET used_at = $2
		WHERE id = $1 AND used_at IS NULL AND expires_at > $2
		RETURNING COALESCE(namespace::text, ''), name, COALESCE(file_id::text, ''), COALESCE(password_hash, ''), allowed_emails, client`,
		id, s.nowUTC()).Scan(&ns, &name, &fileID, &hash, &emails, &client)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = s.UploadLink(ctx, id)
		if err == nil {
			err = ErrLinkUsed // a concurrent request is using it
		}
		return File{}, err
	}
	if err != nil {
		return File{}, err
	}
	if client == "" {
		client = "upload-url"
	}
	var f File
	if fileID != "" {
		f, err = s.Replace(ctx, fileID, ReplaceInput{ContentType: in.ContentType, Body: in.Body, Size: in.Size, Client: client})
	} else {
		if name == "" {
			name = in.Name
		}
		f, err = s.upload(ctx, UploadInput{Namespace: ns, Name: name, ContentType: in.ContentType, Body: in.Body, Size: in.Size, AllowedEmails: emails, Client: client}, hash)
	}
	if err != nil {
		if _, releaseErr := s.db.Exec(context.WithoutCancel(ctx), `UPDATE upload_links SET used_at = NULL WHERE id = $1`, id); releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
		return File{}, err
	}
	return f, nil
}
