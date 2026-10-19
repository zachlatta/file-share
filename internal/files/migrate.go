package files

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrations are applied in order, once each. Never edit a shipped entry;
// append a new one.
var migrations = []string{
	`CREATE TABLE files (
		id uuid PRIMARY KEY,
		namespace uuid NOT NULL,
		name text NOT NULL,
		password_hash text,
		current_version integer NOT NULL,
		created_at timestamptz NOT NULL,
		updated_at timestamptz NOT NULL,
		deleted_at timestamptz
	);
	CREATE UNIQUE INDEX files_live_path ON files (namespace, name) WHERE deleted_at IS NULL;
	CREATE INDEX files_updated ON files (updated_at DESC);
	CREATE INDEX files_deleted ON files (deleted_at) WHERE deleted_at IS NOT NULL;
	CREATE TABLE versions (
		file_id uuid NOT NULL REFERENCES files (id) ON DELETE CASCADE,
		number integer NOT NULL,
		blob_key text NOT NULL,
		size bigint NOT NULL,
		content_type text NOT NULL,
		sha256 text NOT NULL,
		created_at timestamptz NOT NULL,
		created_by text,
		note text,
		superseded_at timestamptz,
		PRIMARY KEY (file_id, number)
	);
	CREATE INDEX versions_blob ON versions (blob_key);
	CREATE INDEX versions_superseded ON versions (superseded_at) WHERE superseded_at IS NOT NULL;`,
	// Emails (or "@domain" entries) allowed to open a file after signing in
	// with Hack Club Auth. Empty means no email restriction.
	`ALTER TABLE files ADD COLUMN allowed_emails text[] NOT NULL DEFAULT '{}';`,
	// Audit log of access to restricted files. No foreign key: the trail
	// outlives the file, so name and namespace are copied in.
	`CREATE TABLE access_events (
		id bigserial PRIMARY KEY,
		at timestamptz NOT NULL,
		file_id uuid,
		namespace uuid,
		name text NOT NULL DEFAULT '',
		version integer NOT NULL DEFAULT 0,
		event text NOT NULL,
		via text NOT NULL DEFAULT '',
		email text NOT NULL DEFAULT '',
		ip text NOT NULL DEFAULT '',
		country text NOT NULL DEFAULT '',
		user_agent text NOT NULL DEFAULT '',
		referer text NOT NULL DEFAULT '',
		remote_addr text NOT NULL DEFAULT '',
		forwarded_for text NOT NULL DEFAULT '',
		status integer NOT NULL DEFAULT 0
	);
	CREATE INDEX access_events_file ON access_events (file_id, id DESC);`,
	// Single-use upload links handed out by create_upload_url. The link,
	// not the request, decides where the file goes and who can open it.
	`CREATE TABLE upload_links (
		id uuid PRIMARY KEY,
		namespace uuid,
		name text NOT NULL DEFAULT '',
		file_id uuid,
		password_hash text,
		allowed_emails text[] NOT NULL DEFAULT '{}',
		client text NOT NULL DEFAULT '',
		created_at timestamptz NOT NULL,
		expires_at timestamptz NOT NULL,
		used_at timestamptz
	);
	CREATE INDEX upload_links_expires ON upload_links (expires_at);`,
	// A replace link can name the version it expects to replace.
	`ALTER TABLE upload_links ADD COLUMN expected_version integer NOT NULL DEFAULT 0;`,
}

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		// Serialize concurrent starts (e.g. a rolling deploy).
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7316843921)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return err
		}
		var applied int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version), 0) FROM schema_migrations`).Scan(&applied); err != nil {
			return err
		}
		for i := applied; i < len(migrations); i++ {
			if _, err := tx.Exec(ctx, migrations[i]); err != nil {
				return fmt.Errorf("migration %d: %w", i+1, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, i+1); err != nil {
				return err
			}
		}
		return nil
	})
}
