# file-share

A personal file host with an MCP server, in the spirit of
[cdn.hackclub.com](https://github.com/hackclub/cdn). Upload, replace, rename, delete, restore,
roll back and password-protect files from any MCP client (Claude, Codex, …), `curl`, or a
script. Every file gets a public URL:

```
https://files.zachlatta.com/<namespace-uuid>/<name>
```

- **Unguessable URLs.** Each upload gets a fresh random UUIDv4 namespace unless you pass an
  existing one, so you can group files (a tiny static site, a folder of photos) under one prefix.
  There is no index or listing anywhere public.
- **Version history.** Replacing a file keeps its URL and adds a version. Older versions stay
  readable and can be rolled back.
- **Recoverable deletes.** Deleted files and replaced versions are kept for `RETENTION_DAYS`
  (default 30), during which `restore_file` / `rollback_file` bring them back. An hourly job
  then purges them. `purge_file` destroys a file immediately, for things uploaded by mistake.
- **Passwords.** Per-file passwords (bcrypt). Visitors get a password page, and the unlock
  cookie is bound to the current password, so changing it locks out old sessions. Scripts can
  use `?password=` or HTTP Basic auth.
- **Large files.** `create_upload_url` returns a short-lived signed URL that takes a plain
  `curl --upload-file`, so agents never base64 big files through a chat message. Cloudflare
  rejects request bodies over 100 MB, so bigger files go up in parts: `PUT <url>?part=1..N`
  (each part 90 MB or less), then `POST <url>?complete=N`. The tool returns a ready-made
  `curl_chunked` script. Unfinished parts are deleted after 24 hours.
  `create_download_url` does the same for downloads, including old versions, password-protected
  files and deleted files.

## MCP tools

| Area | Tools |
| --- | --- |
| Upload | `upload_file` (text, base64 or `source_url`), `create_upload_url`, `replace_file` |
| Read | `read_file`, `create_download_url`, `get_file`, `list_files`, `list_versions`, `get_stats` |
| History | `rollback_file`, `delete_file`, `restore_file`, `purge_file` |
| Manage | `rename_file`, `set_password`, `remove_password` |

Tools accept a file by ID, public URL, or `namespace/name`.

## Authentication

This is the same design as the personal data warehouse:

- **MCP clients use OAuth 2.1.** The server supports dynamic client registration and S256 PKCE.
  The authorize page asks for a client name and for the server's pre-shared `MCP_SECRET`. Client
  IDs, codes, access tokens (24 h) and refresh tokens (1 year) are HMAC-signed with the secret,
  so auth needs no database. Rotating `MCP_SECRET` revokes everything.
- **Scripts use a static bearer:** `Authorization: Bearer <client_name>:<MCP_SECRET>`.
- **Signed upload and download URLs** carry their own expiring HMAC grant.

## HTTP API

```sh
AUTH="Authorization: Bearer laptop:$MCP_SECRET"
curl -H "$AUTH" -F file=@photo.jpg https://files.zachlatta.com/api/files             # upload
curl -H "$AUTH" --data-binary @notes.md "https://files.zachlatta.com/api/files?name=notes.md&namespace=<uuid>&password=pw"
curl -H "$AUTH" -X PUT --data-binary @v2.jpg https://files.zachlatta.com/api/files/<id>/content   # replace
curl -H "$AUTH" "https://files.zachlatta.com/api/files?q=photo&deleted=false"         # list
curl -H "$AUTH" -X DELETE https://files.zachlatta.com/api/files/<id>                  # delete
curl -H "$AUTH" -X POST https://files.zachlatta.com/api/files/<id>/restore            # restore
```

The same 100 MB per-request ceiling applies to `/api/files` through the public hostname. Use a
signed upload URL for anything larger.

## Serving

- `GET /<ns>/<name>` serves the current version with range requests, ETags and
  `Content-Disposition: inline`. Add `?download` to get an attachment instead.
- `GET /<ns>/` serves `index.html` if the namespace has one.
- HTML, SVG and XML run under `Content-Security-Policy: sandbox` without `allow-same-origin`.
  Uploaded pages can run scripts, but in an opaque origin, so they can never act as this site,
  whose OAuth endpoints and password cookies share the origin.

## Storage

- **PostgreSQL** holds metadata in two tables, `files` and `versions`. Migrations run at
  startup.
- **S3-compatible object storage** holds bytes. Every version is written once under a random
  key and never modified. Rollback reuses the old version's object. A purge deletes an object
  only when no remaining version references it. Object-store versioning is not needed, so this
  works on Garage, MinIO, R2 or S3. Addressing is path-style.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `MCP_SECRET` | required, 24+ chars | OAuth authorize secret and static API bearer |
| `PUBLIC_URL` | `http://<ADDR>` | Public origin; https unless loopback |
| `ADDR` | `127.0.0.1:8080` (`0.0.0.0:8080` in Docker) | Listen address |
| `DATABASE_URL` | required | PostgreSQL URL |
| `S3_ENDPOINT` | required | e.g. `http://garage.internal:3900` |
| `S3_REGION` | `us-east-1` | SigV4 region |
| `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY` | required | Bucket and credentials |
| `RETENTION_DAYS` | `30` | How long deleted files and replaced versions are kept |
| `MAX_UPLOAD_MB` | `5120` | Per-file limit |
| `SOURCE_COMMIT` | `dev` | Version on `/healthz` (Coolify sets it) |

`source_url` uploads refuse private, loopback, link-local and CGNAT/tailnet addresses, so a
public file can never be made from something only the server can reach.

## Development

```sh
cp .env.example .env
make test   # gofmt check, go vet, go test -race ./...
make run
```

Tests use real PostgreSQL. Set `FILE_SHARE_TEST_DATABASE_URL`, or have `initdb`/`pg_ctl` on the
machine and the tests start a throwaway cluster. CI uses a Postgres service container. S3 is
tested against an in-process fake (gofakes3). Set `FILE_SHARE_TEST_S3_ENDPOINT`, `_BUCKET`,
`_REGION`, `_ACCESS_KEY` and `_SECRET_KEY` to also run the storage contract against a real
bucket.

## Deployment

The `Dockerfile` builds a static binary on Alpine with a `/healthz` check. `/healthz` always
returns 200 and reports `storage` as `ok` or the error, so a brief object-store outage never
causes restart loops. The container is stateless; mount nothing.
