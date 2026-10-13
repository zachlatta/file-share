# Repository guidelines

## Development workflow

- This is a Go repository. Keep code formatted with `gofmt`.
- Use test-driven development for every behavior change. Write or update a test first and
  confirm it fails for the expected reason. Then implement the smallest change that passes,
  and refactor with the tests green.
- `make test` (gofmt check, `go vet`, `go test -race ./...` against real PostgreSQL) is the full
  verification. Run it end to end before finishing, and also test the affected behavior by
  hand. Report both results.
- When asked to change an existing flow, replace it completely and remove the old code.

## Invariants

- Blobs are immutable. Never overwrite an object key. A new version gets a new key; a rollback
  reuses an existing key. Delete a blob only after no `versions` row references it.
- Deletes are soft until the retention window passes. Only `Purge` (scheduled) and `PurgeFile`
  (explicit, `confirm=true`) destroy data.
- Namespaces are random UUIDv4s. Never add a public listing, directory index, or any endpoint
  that reveals namespaces or names without auth.
- Auth stays stateless and HMAC-signed with `MCP_SECRET`. Every token type carries a distinct
  `type`, and verification checks it.
- Auth must never depend on ambient cookies (uploaded HTML runs on this origin unsandboxed). OAuth uses the typed secret, the API uses bearer tokens, password cookies stay HttpOnly and per-file, and Hack Club sign-in cookies stay HttpOnly, signed and per-namespace, with each file checking its own allow list on every request.
- `source_url` fetching must keep refusing private, loopback, link-local and CGNAT addresses.
- Never log query strings, passwords, or `/upload/` and `/download/` tokens.
- Migrations are append-only: add a new entry and never edit a shipped one.

## Public repository safety

- Everything committed here is public. Never commit secrets, `.env`, credentials, personal data
  or private URLs.
- Before committing, review the complete diff and staged file list.

## Commits

- Commit finished, verified work to `main` and push. Never push failing work.
