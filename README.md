# file-share

A personal file host with an MCP server, in the spirit of
[cdn.hackclub.com](https://github.com/hackclub/cdn). Upload, replace, rename, delete, restore,
roll back and password-protect files from any MCP client (Claude, Codex, …), `curl`, or a
script. Every file gets a public URL:

```
https://files.zachlatta.com/<namespace-uuid>/<name>
```

- **Unguessable URLs.** Each upload gets a fresh random UUIDv4 namespace unless you pass an
  existing one (its UUID or URL), so you can group files (a tiny static site, a folder of photos)
  under one prefix. A namespace that holds no file is refused, so you cannot pick a guessable one.
  There is no index or listing anywhere public.
- **Version history.** Replacing a file keeps its URL and adds a version. Older versions stay
  readable and can be rolled back.
- **Recoverable deletes.** Deleted files and replaced versions are kept for `RETENTION_DAYS`
  (default 30), during which `restore_file` / `rollback_file` bring them back. An hourly job
  then purges them. `purge_file` destroys a file immediately, for things uploaded by mistake.
- **Recoverable expiry.** Set `expires_at` (RFC 3339) or `expires_in_days` (positive whole
  days) on `upload_file`, `create_upload_url`, or POST `/api/files`. These options are
  mutually exclusive; days are resolved when settings are accepted, including when a link
  is created. The hourly purge soft-deletes due files and records an `expired` audit event,
  even for public files. The normal retention window starts at soft deletion. Restoring
  clears a passed expiry and preserves a future one. Use `set_expiry` or PATCH `/api/files/<id>`
  to change expiry; `expires_at: null` clears it, while PATCH omission preserves it. Replacement
  uploads preserve expiry; replacement links reject expiry options, so update it separately.
  Get/list metadata and the authenticated admin file table show `expires_at`.
- **Share with specific people.** Restrict a file to email addresses (or `@domain.com` for a
  whole domain). Visitors click **Sign in with Hack Club**, log in with
  [Hack Club Auth](https://auth.hackclub.com), and only a verified email on the list opens the
  file. The sign-in is remembered for 30 days per namespace, and every request checks the
  file's current list, so removing someone takes effect immediately. This is the preferred way
  to share privately.
- **Passwords.** Per-file passwords (bcrypt), for people without a Hack Club account. Visitors
  get a password page, and the unlock cookie is bound to the current password, so changing it
  locks out old sessions. Scripts can use `?password=` or HTTP Basic auth. If a file has both a
  password and allowed emails, either one opens it. Every wrong password, however it is sent,
  is delayed, logged and counted: after 20 wrong guesses at one file in 15 minutes, password
  attempts on it get `429` until the window ends. Visitors who already unlocked it keep access.
- **Audit log and admin dashboard.** Every access to a password- or email-protected file is
  recorded: views (and how access was granted), visitors turned away at the gate, wrong
  passwords, and Hack Club sign-ins, with IP, country, user agent, referrer (query string
  removed) and the signed-in email. Signed download URLs for protected files are logged too.
  Public views are not logged; automatic expiry is logged for every file. Browse it at `/admin` after signing in with `ADMIN_TOKEN`, or
  ask an agent through `get_access_log`. The log outlives purged files.
- **Upload links, no secret.** `create_upload_url` returns a one-off signed URL, so an MCP
  client can upload a local or large file with plain `curl` and never holds `MCP_SECRET` or
  base64s big files through a chat message. The link fixes the name (optional: omit it to use
  the uploaded file's name), namespace, password and allowed emails; the upload only sends the
  bytes. It works once: a second upload returns `410 Gone`. A failed upload releases it for a
  retry. The expiry is a deadline to start (default 60 minutes, max 24 hours).
  Once a part is stored, the upload stays valid until 24 hours after the latest stored part. Proxies cap request
  bodies (Cloudflare rejects bodies over 100 MB) and time out slow single-stream uploads, so
  files over 20 MB go up in parts: `PUT <url>?part=1..N` (each part 20 MB or less), then poll
  `POST <url>?complete=N` (plus `&name=` if the link has no name), which assembles the parts in
  the background and returns `202 Accepted` (`{"status":"assembling"}`) if still running after
  60 seconds, then `201 Created` (or `200 OK` when replacing) with the file JSON once done. The
  tool returns a ready-made `curl_chunked` script (requires curl, split and jq) with retries and completion polling.
  Rerun it after interruption: it queries `GET <upload_url>?status` and skips stored parts
  whose sizes match. Status returns `{parts:[{n,size}],state:"pending|assembling|done",file?:...}`
  without consuming the link; completed links return the resulting file until hourly cleanup
  removes them, only after the start deadline and at least 24 hours after the upload
  was claimed for completion. Use the same local
  file when resuming: matching sizes do not verify matching content. Pass
  `local_path` and both commands name your file, so they run as is; without it they use a
  `./LOCAL_FILE` placeholder. All unfinished parts are retained until 24 hours after the latest part.
  `create_download_url` does the same for downloads, including old versions, password-protected
  files and deleted files.

## MCP tools

| Area | Tools |
| --- | --- |
| Upload | `upload_file` (text, base64 or `source_url`), `create_upload_url`, `replace_file` |
| Read | `read_file`, `create_download_url`, `get_file`, `list_files`, `list_versions`, `get_access_log`, `get_request_log`, `get_listening`, `get_stats` |
| History | `rollback_file`, `delete_file`, `restore_file`, `purge_file` |
| Manage | `rename_file`, `set_expiry`, `set_allowed_emails`, `set_password`, `remove_password` |

Tools accept a file by ID, public URL, or `namespace/name`.

`upload_file` and `replace_file` take exactly one content source. An empty `content_text` or
`content_base64` is a source: it makes an empty file (such as a `.nojekyll` placeholder) or blanks
an existing one. An empty request body does the same on the HTTP API.

## Authentication

This is the same design as the personal data warehouse:

- **MCP clients use OAuth 2.1.** The server supports dynamic client registration and S256 PKCE.
  The authorize page asks for a client name and for the server's pre-shared `MCP_SECRET`. Client
  IDs, codes, access tokens (24 h) and refresh tokens (1 year) are HMAC-signed with the secret,
  so auth needs no database. Rotating `MCP_SECRET` revokes everything. The secret field is a
  masked text input, not a password field, so browsers and password managers do not save it or
  autofill it: uploaded HTML runs on this origin, and a credential saved for the origin could
  be filled into an uploaded page.
- **Scripts use a static bearer:** `Authorization: Bearer <client_name>:<MCP_SECRET>`. It works
  on the HTTP API and on `/mcp`, so a script can call any tool with one JSON-RPC request and
  no OAuth flow (see below).
- **Signed upload and download URLs** carry their own expiring HMAC grant. An upload URL
  points at a single-use `upload_links` row that holds the link's settings and is claimed
  atomically, so it can be used once.
- **Visitors to email-restricted files** sign in with Hack Club Auth (OpenID Connect,
  `openid email` scopes). The server exchanges the code with its client secret, reads the
  verified email from the userinfo endpoint, and stores it in an HMAC-signed, HttpOnly cookie
  scoped to that file's namespace. The OAuth `state` is signed and bound to the browser by a
  short-lived cookie, and it can only return to a `/<namespace>/…` path.

- **The admin dashboard** (`/admin`) takes `ADMIN_TOKEN`, which is separate from `MCP_SECRET`
  and only reads the audit log. The page keeps the token in memory and sends it as a bearer
  header to `/api/admin/*`; it never sets a cookie or uses web storage, because uploaded HTML
  runs on this origin. Its token field is masked text, not a password field, for the same
  reason, so the browser does not save the token either. `Cross-Origin-Opener-Policy:
  same-origin` and `frame-ancestors 'none'` stop an uploaded page from opening or framing
  the dashboard. Reloading signs you out.

## HTTP API

```sh
AUTH="Authorization: Bearer laptop:$MCP_SECRET"
curl -H "$AUTH" -F file=@photo.jpg https://files.zachlatta.com/api/files             # upload
curl -H "$AUTH" --data-binary @notes.md "https://files.zachlatta.com/api/files?name=notes.md&namespace=<uuid>&password=pw"
curl -H "$AUTH" -F file=@plan.pdf --form-string emails=zach@hackclub.com,@hackclub.com https://files.zachlatta.com/api/files  # share with people
curl -H "$AUTH" -X PUT --data-binary @v2.jpg https://files.zachlatta.com/api/files/<id>/content   # replace
curl -H "$AUTH" -X PUT --data-binary @v2.jpg "https://files.zachlatta.com/api/files/<id>/content?expected_version=1"  # replace only if still v1, else 409
curl -H "$AUTH" -o out.jpg "https://files.zachlatta.com/api/files/<id>/content?version=1"  # exact bytes, even restricted or deleted
curl -H "$AUTH" -X PATCH -d '{"allowed_emails":["max@hackclub.com"],"password":""}' https://files.zachlatta.com/api/files/<id>  # who can open it; "" removes the password, [] makes it public; also "name"
curl -H "$AUTH" -X PATCH -d '{"expires_in_days":30}' https://files.zachlatta.com/api/files/<id>  # expire in 30 days; {"expires_at":null} clears
curl -H "$AUTH" https://files.zachlatta.com/api/files/<id>/versions                    # history
curl -H "$AUTH" -X POST "https://files.zachlatta.com/api/files/<id>/rollback?version=1"  # roll back
curl -H "$AUTH" "https://files.zachlatta.com/api/files?q=photo&deleted=false"         # list
curl -H "$AUTH" -X DELETE https://files.zachlatta.com/api/files/<id>                  # delete
curl -H "$AUTH" -X POST https://files.zachlatta.com/api/files/<id>/restore            # restore
```

POST expiry options are query parameters for raw bytes or multipart form fields. PATCH accepts
them as JSON fields. Expiry may be in the past; deletion happens on the next purge.

`<id>` may also be the URL-escaped `namespace%2Fname`. Any MCP tool works from a shell with the
same bearer, as a single stateless JSON-RPC call:

```sh
curl -sS -H "$AUTH" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' https://files.zachlatta.com/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_access_log","arguments":{"limit":20}}}' \
  | jq .result.structuredContent
```

`/api/files` is a single-request upload endpoint (capped at 100 MB through Cloudflare and bound
by the origin proxy's request read timeout). Use a signed upload URL (`create_upload_url`) with
`curl_chunked` for anything over 20 MB. Agents connected over MCP should use `create_upload_url`
instead of this API, so they never need the secret.

## Serving

- `GET /<ns>/<name>` serves the current version with range requests, ETags and
  `Content-Disposition: inline`. Add `?download` to get an attachment instead.
- `GET /<ns>/` serves `index.html` if the namespace has one.
- **Markdown opens as a readable page in a browser, and stays a file everywhere else.** A file
  stored as `text/markdown`, or as `text/plain` with a `.md`/`.markdown` name, is rendered like a
  GitHub Gist (GitHub-flavored Markdown: tables, task lists, footnotes; light and dark theme)
  when a browser navigates to it (`Sec-Fetch-Dest: document`). A client that sends no fetch
  metadata gets the page only if its `Accept` names `text/html`, so `curl -H 'Accept: text/html'`
  and link-preview bots that send it get HTML too. Default `curl`, `wget`, most HTTP libraries,
  `fetch()`, iframes and range requests get the exact stored bytes and Content-Type as before.
  The page header has **Raw** (`?raw=1`, the bytes inline) and **Download** (`?download=1`)
  links; if the page was opened with `?password=`, the links carry it over. Both forms send
  `Vary: Accept, Sec-Fetch-Dest`; the page is `Cache-Control: private, no-store` and the bytes
  `private, no-cache`, so no shared cache (Cloudflare ignores `Vary`) mixes them, and Markdown
  is not cached at the edge. Each page view reads the file and renders it again.
  The stored charset is honoured (for example `iso-8859-1`, `windows-1252`); no charset means
  UTF-8. Files whose bytes are not valid in that charset, whose charset is unknown, or that
  are over 512 KB are served raw. Raw HTML in the Markdown is dropped and the output is
  sanitized (bluemonday); the page has a strict CSP with no script. Relative links and images
  resolve next to the file. The page goes through the same password, Hack Club sign-in and
  audit checks as the file.
- HTML is served as an ordinary page, so uploaded sites and maps work fully. A CSP sandbox was
  tried and dropped, because the opaque origin it creates disables Cache Storage and broke a
  MapLibre map. This is safe because only the owner can upload, OAuth and the API never use
  ambient cookies, and password cookies are HttpOnly.

## Request log and listening

- Every file served from `/<ns>/<name>` adds a row to `file_requests`: time, method, status,
  the first byte sent and how many bytes actually went out, the file size, IP, country, user
  agent, referrer and duration. Query strings are never stored and referrers lose theirs.
- Audio and video are sent with `Cache-Control: private, no-cache`, so Cloudflare does not
  cache them and every range request a podcast player makes reaches the log.
- `get_listening` (MCP) and `/admin` (Listening) merge each listener's byte ranges (a listener
  is one IP and user agent) into coverage per slice of the file. For a constant-bitrate MP3 a
  slice of bytes is the same slice of time, so this shows which sections were streamed. A
  player that downloads a whole episode shows full coverage whether or not it was played;
  no server can see playback inside a downloaded file.

## Storage

- **PostgreSQL** holds metadata (`files`, `versions`) and the logs (`access_events`,
  `file_requests`). Migrations run at
  startup.
- **S3-compatible object storage** holds bytes. Every version is written once under a random
  key and never modified. Rollback reuses the old version's object. A purge deletes an object
  only when no remaining version references it. If that delete fails (storage down), or a
  failed upload leaves its object behind, the hourly purge lists `blobs/` and deletes any
  object that is over 24 hours old and that no version references. Object-store versioning
  is not needed, so this works on Garage, MinIO, R2 or S3. Addressing is path-style.

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
| `HCA_CLIENT_ID`, `HCA_CLIENT_SECRET` | unset (email restriction off) | Hack Club Auth app credentials; its redirect URI must be `PUBLIC_URL/oauth/callback` |
| `HCA_URL` | `https://auth.hackclub.com` | Hack Club Auth origin |
| `ADMIN_TOKEN` | unset (dashboard off) | 24+ chars, different from `MCP_SECRET`; unlocks `/admin` |
| `CLIENT_IP_HEADER` | unset (socket address) | Trusted proxy header with the visitor IP, e.g. `CF-Connecting-IP` behind Cloudflare. Only set it if the origin can't be reached except through that proxy, since anyone else can forge it |

`source_url` uploads refuse private, loopback, link-local and CGNAT/tailnet addresses, so a
public file can never be made from something only the server can reach.

## Development

```sh
make dev-env    # .env from .env.example, with a fresh MCP_SECRET
make dev-deps   # PostgreSQL and Garage on loopback (compose.dev.yaml)
make test       # gofmt check, go vet, go test -race ./...
make run
```

`paseo.json` sets up the same thing for Paseo: a new worktree copies `.env` from the main
checkout (or runs `make dev-env`), and the `serve` script starts the dependencies and the server
on the port Paseo assigns.

Tests use real PostgreSQL. Set `FILE_SHARE_TEST_DATABASE_URL`, or have `initdb`/`pg_ctl` on the
machine and the tests start a throwaway cluster. CI uses a Postgres service container. S3 is
tested against an in-process fake (gofakes3). Set `FILE_SHARE_TEST_S3_ENDPOINT`, `_BUCKET`,
`_REGION`, `_ACCESS_KEY` and `_SECRET_KEY` to also run the storage contract against a real
bucket.

## Deployment

The `Dockerfile` builds a static binary on Alpine with a `/healthz` check. `/healthz` always
returns 200, so a brief object-store outage never causes restart loops. When storage is
unreachable, `status` is `degraded` and `storage` names the failed part and a coarse cause
(for example `object store: connection refused`, `postgres: timed out`); otherwise both are
`ok`. `/healthz` is public, so the full error, with addresses and the bucket name, goes only to
the server log (`health check failed`).
The container is stateless; mount nothing.
