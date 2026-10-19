package files

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AccessEvent is one audit-log entry for a restricted file: a view, a denial
// at the gate, a password attempt, or a Hack Club sign-in.
type AccessEvent struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	FileID    string    `json:"file_id,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name,omitempty"`
	Version   int       `json:"version,omitempty"`
	// Event is view, denied, wrong_password, unlock, sign_in or
	// sign_in_failed.
	Event string `json:"event"`
	// Via is how access was granted: password_cookie, password_form,
	// password_query, basic_auth, email or download_url.
	Via          string `json:"via,omitempty"`
	Email        string `json:"email,omitempty"`
	IP           string `json:"ip,omitempty"`
	Country      string `json:"country,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	Referer      string `json:"referer,omitempty"`
	RemoteAddr   string `json:"remote_addr,omitempty"`
	ForwardedFor string `json:"forwarded_for,omitempty"`
	Status       int    `json:"status,omitempty"`
}

const accessColumns = `id, at, COALESCE(file_id::text, ''), COALESCE(namespace::text, ''), name, version, event, via, email,
	ip, country, user_agent, referer, remote_addr, forwarded_for, status`

// RecordAccess appends an event to the audit log. At defaults to now.
func (s *Service) RecordAccess(ctx context.Context, e AccessEvent) error {
	if e.At.IsZero() {
		e.At = s.nowUTC()
	}
	_, err := s.db.Exec(ctx, `INSERT INTO access_events (at, file_id, namespace, name, version, event, via, email, ip, country,
		user_agent, referer, remote_addr, forwarded_for, status)
		VALUES ($1, NULLIF($2, '')::uuid, NULLIF($3, '')::uuid, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		e.At, uuidOrEmpty(e.FileID), uuidOrEmpty(e.Namespace), clip(e.Name, 255), e.Version, clip(e.Event, 32), clip(e.Via, 32),
		clip(e.Email, 254), clip(e.IP, 64), clip(e.Country, 8), clip(e.UserAgent, 512), clip(e.Referer, 512),
		clip(e.RemoteAddr, 64), clip(e.ForwardedFor, 256), e.Status)
	return err
}

func uuidOrEmpty(v string) string {
	if _, err := uuid.Parse(v); err != nil {
		return ""
	}
	return v
}

type AccessQuery struct {
	FileID string
	Event  string
	// Search matches a case-insensitive substring of the email, IP, user
	// agent or file name.
	Search string
	// Before returns only events with a smaller ID, for paging.
	Before int64
	Limit  int
}

// ListAccess returns audit-log events, newest first.
func (s *Service) ListAccess(ctx context.Context, q AccessQuery) ([]AccessEvent, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	where, args := []string{"true"}, []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if q.FileID != "" {
		if _, err := uuid.Parse(q.FileID); err != nil {
			return nil, fmt.Errorf("%w: file ID must be a UUID", ErrInvalid)
		}
		add("file_id = $%d", q.FileID)
	}
	if q.Event != "" {
		add("event = $%d", q.Event)
	}
	if q.Search != "" {
		pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(q.Search) + "%"
		add("(email ILIKE $%[1]d OR ip ILIKE $%[1]d OR user_agent ILIKE $%[1]d OR name ILIKE $%[1]d)", pattern)
	}
	if q.Before > 0 {
		add("id < $%d", q.Before)
	}
	args = append(args, q.Limit)
	rows, err := s.db.Query(ctx, `SELECT `+accessColumns+` FROM access_events WHERE `+strings.Join(where, " AND ")+
		fmt.Sprintf(` ORDER BY id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (AccessEvent, error) {
		var e AccessEvent
		err := row.Scan(&e.ID, &e.At, &e.FileID, &e.Namespace, &e.Name, &e.Version, &e.Event, &e.Via, &e.Email,
			&e.IP, &e.Country, &e.UserAgent, &e.Referer, &e.RemoteAddr, &e.ForwardedFor, &e.Status)
		e.At = e.At.UTC()
		return e, err
	})
}

// RestrictedFile summarizes a live file that has a password or allowed
// emails, with its audit-log totals.
type RestrictedFile struct {
	File
	Views int `json:"views"`
	// Viewers counts distinct signed-in emails, or IPs for password views.
	Viewers      int        `json:"viewers"`
	Denied       int        `json:"denied"`
	LastViewedAt *time.Time `json:"last_viewed_at,omitempty"`
}

// RestrictedFiles lists live restricted files, most recently updated first.
func (s *Service) RestrictedFiles(ctx context.Context) ([]RestrictedFile, error) {
	rows, err := s.db.Query(ctx, `SELECT `+fileColumns+`,
			COALESCE(a.views, 0), COALESCE(a.viewers, 0), COALESCE(a.denied, 0), a.last_view`+fileFrom+`
		LEFT JOIN LATERAL (
			SELECT count(*) FILTER (WHERE event = 'view') AS views,
				count(DISTINCT CASE WHEN event = 'view' THEN COALESCE(NULLIF(email, ''), ip) END) AS viewers,
				count(*) FILTER (WHERE event = 'denied') AS denied,
				max(at) FILTER (WHERE event = 'view') AS last_view
			FROM access_events WHERE file_id = f.id) a ON true
		WHERE f.deleted_at IS NULL AND (f.password_hash IS NOT NULL OR cardinality(f.allowed_emails) > 0)
		ORDER BY f.updated_at DESC, f.id LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RestrictedFile
	for rows.Next() {
		var r RestrictedFile
		err := rows.Scan(&r.ID, &r.Namespace, &r.Name, &r.passwordHash, &r.Version, &r.CreatedAt, &r.UpdatedAt, &r.DeletedAt,
			&r.Size, &r.ContentType, &r.SHA256, &r.AllowedEmails, &r.Views, &r.Viewers, &r.Denied, &r.LastViewedAt)
		if err != nil {
			return nil, err
		}
		s.decorate(&r.File)
		if r.LastViewedAt != nil {
			at := r.LastViewedAt.UTC()
			r.LastViewedAt = &at
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
