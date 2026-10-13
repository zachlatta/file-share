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
