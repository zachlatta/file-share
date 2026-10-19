// Package mcpserver exposes file sharing as MCP tools.
package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zachlatta/file-share/internal/auth"
	"github.com/zachlatta/file-share/internal/fetch"
	"github.com/zachlatta/file-share/internal/files"
)

const (
	defaultReadBytes = 5 << 20
	maxReadBytes     = 25 << 20
	maxInlineImage   = 5 << 20
)

type Config struct {
	Files   *files.Service
	Auth    *auth.Service
	Fetcher *fetch.Fetcher
	Version string
}

type server struct {
	files   *files.Service
	auth    *auth.Service
	fetcher *fetch.Fetcher
}

const fileRef = "The file: its ID, its public URL, or \"namespace/name\". Deleted files can only be referenced by ID."

type ContentInput struct {
	ContentText   string `json:"content_text,omitempty" jsonschema:"File content as UTF-8 text. Use for text files."`
	ContentBase64 string `json:"content_base64,omitempty" jsonschema:"File content, base64-encoded. Use for binary files that fit in a message; for large files use create_upload_url instead."`
	SourceURL     string `json:"source_url,omitempty" jsonschema:"A public http(s) URL for the server to download the content from."`
	ContentType   string `json:"content_type,omitempty" jsonschema:"MIME type. Optional: detected from the name and content when omitted."`
}

type UploadInput struct {
	Name          string   `json:"name,omitempty" jsonschema:"File name, which becomes the last part of the URL. May contain '/' to make folders. Defaults to the source_url's file name."`
	Namespace     string   `json:"namespace,omitempty" jsonschema:"Existing namespace UUID to add this file to (to group files, e.g. a small website). Omit to create a new unguessable namespace."`
	Password      string   `json:"password,omitempty" jsonschema:"Optional password visitors must enter to open the file."`
	AllowedEmails []string `json:"allowed_emails,omitempty" jsonschema:"Optional: only these people can open the file, after signing in with Hack Club Auth. Exact addresses, or '@domain.com' for a whole domain. Preferred over a password for sharing with specific people."`
	ContentInput
}

type ReplaceInput struct {
	File            string `json:"file" jsonschema:"The file: its ID, its public URL, or namespace/name."`
	ExpectedVersion int    `json:"expected_version,omitempty" jsonschema:"Optional: the version you read before editing (from get_file). The call fails, changing nothing, if the file has moved past it, so concurrent edits are never silently lost; then re-read, merge and retry."`
	ContentInput
}

type FileInput struct {
	File string `json:"file" jsonschema:"The file: its ID, its public URL, or namespace/name. Deleted files can only be referenced by ID."`
}

type ReadInput struct {
	File     string `json:"file" jsonschema:"The file: its ID, its public URL, or namespace/name."`
	Version  int    `json:"version,omitempty" jsonschema:"Version number to read. Default: current."`
	MaxBytes int64  `json:"max_bytes,omitempty" jsonschema:"Refuse files larger than this (default 5 MiB, max 25 MiB). Use create_download_url for bigger files."`
}

type ListInput struct {
	Namespace string `json:"namespace,omitempty" jsonschema:"Only files in this namespace UUID."`
	Query     string `json:"query,omitempty" jsonschema:"Case-insensitive substring of the file name."`
	Deleted   bool   `json:"deleted,omitempty" jsonschema:"List deleted (restorable) files instead of live ones."`
	Limit     int    `json:"limit,omitempty" jsonschema:"Max results (default 100, max 1000)."`
	Offset    int    `json:"offset,omitempty"`
}

type RollbackInput struct {
	File    string `json:"file" jsonschema:"The file: its ID, its public URL, or namespace/name."`
	Version int    `json:"version" jsonschema:"The version number to make current again (see list_versions)."`
}

type RenameInput struct {
	File    string `json:"file" jsonschema:"The file: its ID, its public URL, or namespace/name."`
	NewName string `json:"new_name" jsonschema:"New file name within the same namespace. Changes the URL."`
}

type PasswordInput struct {
	File     string `json:"file" jsonschema:"The file: its ID, its public URL, or namespace/name."`
	Password string `json:"password" jsonschema:"The new password (max 72 bytes)."`
}

type EmailsInput struct {
	File   string   `json:"file" jsonschema:"The file: its ID, its public URL, or namespace/name."`
	Emails []string `json:"emails" jsonschema:"The complete new list: email addresses, or '@domain.com' for a whole domain. An empty list removes the email restriction."`
}

type AccessLogInput struct {
	File   string `json:"file,omitempty" jsonschema:"Only events for this file: its ID, public URL, or namespace/name. Omit for all files."`
	Event  string `json:"event,omitempty" jsonschema:"Only this event: view, denied, wrong_password, unlock, sign_in or sign_in_failed."`
	Search string `json:"search,omitempty" jsonschema:"Case-insensitive substring of the email, IP, user agent or file name."`
	Before int64  `json:"before,omitempty" jsonschema:"Only events with an ID below this, for paging."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Max events (default 200, max 1000)."`
}

type accessLogOutput struct {
	Events []files.AccessEvent `json:"events"`
}

type PurgeInput struct {
	File    string `json:"file" jsonschema:"The file: its ID, its public URL, or namespace/name."`
	Confirm bool   `json:"confirm" jsonschema:"Must be true. Purging is immediate and irreversible: all versions are destroyed."`
}

type UploadURLInput struct {
	Name            string   `json:"name,omitempty" jsonschema:"Name for the new file. Omit to use the uploaded file's own name."`
	Namespace       string   `json:"namespace,omitempty" jsonschema:"Existing namespace UUID for the new file. Omit for a new namespace."`
	Password        string   `json:"password,omitempty" jsonschema:"Optional password visitors must enter to open the new file."`
	AllowedEmails   []string `json:"allowed_emails,omitempty" jsonschema:"Optional: only these people can open the new file, after signing in with Hack Club Auth. Exact addresses, or '@domain.com' for a whole domain."`
	File            string   `json:"file,omitempty" jsonschema:"To replace an existing file instead: its ID, URL or namespace/name. Its name, password and allowed emails are kept."`
	ExpectedVersion int      `json:"expected_version,omitempty" jsonschema:"With file: the version you read before editing. The upload is refused if the file has moved past it by then."`
	ExpiresMinutes  int      `json:"expires_minutes,omitempty" jsonschema:"How long the URL works if unused (default 60, max 1440)."`
}

type DownloadURLInput struct {
	File           string `json:"file" jsonschema:"The file: its ID, its public URL, or namespace/name."`
	Version        int    `json:"version,omitempty" jsonschema:"Version number. Default: current."`
	ExpiresMinutes int    `json:"expires_minutes,omitempty" jsonschema:"How long the URL works (default 60, max 10080)."`
}

type Empty struct{}

type readOutput struct {
	File        files.File `json:"file"`
	Version     int        `json:"version"`
	ContentType string     `json:"content_type"`
	Size        int64      `json:"size"`
	Text        string     `json:"text,omitempty"`
	Base64      string     `json:"base64,omitempty"`
}

type fileDetail struct {
	files.File
	Versions []files.Version `json:"versions"`
}

type versionsOutput struct {
	Versions []files.Version `json:"versions"`
}

type listOutput struct {
	Files []files.File `json:"files"`
}

type okOutput struct {
	OK bool `json:"ok"`
}

type uploadURLOutput struct {
	UploadURL string `json:"upload_url"`
	// SingleUse: the URL stops working after one successful upload.
	SingleUse bool      `json:"single_use"`
	ExpiresAt time.Time `json:"expires_at"`
	// URL is the file's public URL once uploaded, when the name is known.
	URL       string `json:"url,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Curl      string `json:"curl"`
	// The public proxy rejects request bodies over 100 MB, so larger files
	// must be sent in parts.
	MaxSingleRequestMB int    `json:"max_single_request_mb"`
	CurlChunked        string `json:"curl_chunked"`
}

type downloadURLOutput struct {
	DownloadURL string    `json:"download_url"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type statsOutput struct {
	files.Stats
	RetentionDays  int    `json:"retention_days"`
	MaxUploadBytes int64  `json:"max_upload_bytes"`
	BaseURL        string `json:"base_url"`
}

func New(cfg Config) *mcp.Server {
	s := &server{files: cfg.Files, auth: cfg.Auth, fetcher: cfg.Fetcher}
	days := int(cfg.Files.Retention().Hours() / 24)
	srv := mcp.NewServer(&mcp.Implementation{Name: "file-share", Title: "file-share", Version: cfg.Version}, &mcp.ServerOptions{
		Instructions: fmt.Sprintf("A personal file host at %s. Every file gets a public URL of the form %s/<namespace-uuid>/<name>; "+
			"namespaces are random UUIDs, so URLs are unguessable but anyone with the link can open the file unless it is restricted. "+
			"To share with specific people, set allowed_emails (or call set_allowed_emails): visitors sign in with Hack Club Auth and only those emails (or '@domain' entries) can open the file. "+
			"A password is the alternative for people without a Hack Club account; if a file has both, either one opens it. "+
			"Upload small files inline (content_text or content_base64), from the web (source_url), or for large or local files call create_upload_url and send the bytes with the curl it returns; that single-use URL needs no secret or API token. "+
			"Replacing a file keeps its URL and adds a version; if another agent may also edit it, pass expected_version (the version you read) so a concurrent edit is refused instead of overwritten. Deleted files and replaced versions are kept for %d days, "+
			"during which restore_file and rollback_file can bring them back; after that they are purged. "+
			"Files are referenced by ID, URL, or namespace/name.", cfg.Files.BaseURL(), cfg.Files.BaseURL(), days),
	})
	closed := false
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closed}
	additive := &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: &closed}
	fetching := &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(true)}
	updating := &mcp.ToolAnnotations{DestructiveHint: ptr(true), IdempotentHint: true, OpenWorldHint: &closed}
	destructive := &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: &closed}

	add(srv, "upload_file", "Upload a new file and get its public URL. Give exactly one of content_text, content_base64 or source_url. Omit namespace for a fresh unguessable URL; pass a namespace to group files. Optionally restrict it to allowed_emails (sign in with Hack Club) or a password.", fetching, s.upload)
	add(srv, "create_upload_url", "Get a single-use URL that accepts one file over HTTP, so a local or large file can be uploaded with curl and no secret. Set name, namespace, password and allowed_emails here; the upload only sends the bytes. Files up to 95 MB: run the returned curl (multipart; omit name to use the local file's name). Larger files: run curl_chunked, which PUTs 90 MB parts with ?part=N and then POSTs ?complete=N. The URL stops working after one successful upload. Pass file to upload a new version of an existing file instead.", additive, s.uploadURL)
	add(srv, "replace_file", "Replace a file's content, keeping its URL and password. The previous content stays available as an older version for the retention window. Give exactly one of content_text, content_base64 or source_url.", fetching, s.replace)
	mcp.AddTool(srv, &mcp.Tool{Name: "read_file", Description: "Read a file's content (current or an older version). Text comes back as text, other files as base64; images are also returned as images.", Annotations: readOnly}, s.read)
	add(srv, "create_download_url", "Get a short-lived private URL for the exact bytes of a version of a file. It works even for restricted (password or email) or deleted files.", readOnly, s.downloadURL)
	add(srv, "get_file", "Get a file's details, including its version history.", readOnly, s.get)
	add(srv, "list_files", "List files, most recently changed first. Set deleted=true to list deleted files that can still be restored.", readOnly, s.list)
	add(srv, "list_versions", "List a file's retained versions, newest first, with when each will be purged.", readOnly, s.versions)
	add(srv, "rollback_file", "Make an older version current again. This adds a new version with the old content; nothing is lost.", additive, s.rollback)
	add(srv, "rename_file", "Rename a file within its namespace. This changes its URL.", updating, s.rename)
	add(srv, "delete_file", fmt.Sprintf("Delete a file. Its URL stops working immediately, but it can be restored with restore_file for %d days.", days), destructive, s.delete)
	add(srv, "restore_file", "Restore a deleted file at its original URL.", additive, s.restore)
	add(srv, "purge_file", "Permanently and immediately destroy a file and all its versions (for example something uploaded by mistake). Irreversible; requires confirm=true.", destructive, s.purge)
	add(srv, "set_password", "Set or change the password visitors must enter to open a file. Old unlock cookies stop working.", updating, s.setPassword)
	add(srv, "remove_password", "Remove a file's password so anyone with the link can open it.", updating, s.removePassword)
	add(srv, "set_allowed_emails", "Set exactly who can open a file: visitors sign in with Hack Club Auth and must use one of these emails (or match an '@domain' entry). Replaces the whole list; an empty list removes the restriction. Takes effect immediately, including for people already signed in.", updating, s.setAllowedEmails)
	add(srv, "get_access_log", "Audit log for password- and email-protected files, newest first: who viewed them (signed-in email, IP, country, user agent, referrer), who was turned away, wrong passwords and Hack Club sign-ins. Public files are not logged.", readOnly, s.accessLog)
	add(srv, "get_stats", "Totals (files, bytes, deleted files, namespaces), the retention window, and the upload size limit.", readOnly, s.stats)
	return srv
}

func add[In, Out any](srv *mcp.Server, name, description string, annotations *mcp.ToolAnnotations, handler func(context.Context, In) (Out, error)) {
	mcp.AddTool(srv, &mcp.Tool{Name: name, Description: description, Annotations: annotations},
		func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
			out, err := handler(ctx, in)
			return nil, out, err
		})
}

func ptr[T any](v T) *T { return &v }

func client(ctx context.Context) string {
	if name := auth.ClientName(ctx); name != "" {
		return name
	}
	return "mcp"
}

// content opens the single content source in in.
func (s *server) content(ctx context.Context, in ContentInput) (body io.Reader, size int64, contentType, suggestedName string, closer func(), err error) {
	sources := 0
	for _, set := range []bool{in.ContentText != "", in.ContentBase64 != "", in.SourceURL != ""} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		return nil, 0, "", "", nil, fmt.Errorf("%w: give exactly one of content_text, content_base64 or source_url", files.ErrInvalid)
	}
	closer = func() {}
	switch {
	case in.ContentText != "":
		return strings.NewReader(in.ContentText), int64(len(in.ContentText)), in.ContentType, "", closer, nil
	case in.ContentBase64 != "":
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(in.ContentBase64))
		if err != nil {
			return nil, 0, "", "", nil, fmt.Errorf("%w: content_base64 is not valid base64: %v", files.ErrInvalid, err)
		}
		return bytes.NewReader(data), int64(len(data)), in.ContentType, "", closer, nil
	default:
		res, err := s.fetcher.Get(ctx, in.SourceURL)
		if err != nil {
			return nil, 0, "", "", nil, err
		}
		contentType = in.ContentType
		if contentType == "" {
			contentType = res.ContentType
		}
		return res.Body, res.ContentLength, contentType, res.Filename, func() { _ = res.Body.Close() }, nil
	}
}

func (s *server) upload(ctx context.Context, in UploadInput) (files.File, error) {
	body, size, contentType, suggested, closer, err := s.content(ctx, in.ContentInput)
	if err != nil {
		return files.File{}, err
	}
	defer closer()
	name := in.Name
	if name == "" {
		name = suggested
	}
	return s.files.Upload(ctx, files.UploadInput{
		Namespace: in.Namespace, Name: name, ContentType: contentType, Body: body, Size: size,
		Password: in.Password, AllowedEmails: in.AllowedEmails, Client: client(ctx),
	})
}

func (s *server) replace(ctx context.Context, in ReplaceInput) (files.File, error) {
	f, err := s.files.Resolve(ctx, in.File)
	if err != nil {
		return files.File{}, err
	}
	body, size, contentType, _, closer, err := s.content(ctx, in.ContentInput)
	if err != nil {
		return files.File{}, err
	}
	defer closer()
	return s.files.Replace(ctx, f.ID, files.ReplaceInput{ContentType: contentType, Body: body, Size: size, Client: client(ctx), ExpectedVersion: in.ExpectedVersion})
}

func (s *server) read(ctx context.Context, _ *mcp.CallToolRequest, in ReadInput) (*mcp.CallToolResult, readOutput, error) {
	f, err := s.files.Resolve(ctx, in.File)
	if err != nil {
		return nil, readOutput{}, err
	}
	limit := in.MaxBytes
	if limit <= 0 {
		limit = defaultReadBytes
	}
	limit = min(limit, maxReadBytes)
	obj, v, err := s.files.Open(ctx, f.ID, in.Version)
	if err != nil {
		return nil, readOutput{}, err
	}
	defer obj.Close()
	if v.Size > limit {
		return nil, readOutput{}, fmt.Errorf("version %d is %d bytes, over the %d byte read limit; raise max_bytes or use create_download_url", v.Number, v.Size, limit)
	}
	data, err := io.ReadAll(io.LimitReader(obj, limit+1))
	if err != nil {
		return nil, readOutput{}, err
	}
	out := readOutput{File: f, Version: v.Number, ContentType: v.ContentType, Size: v.Size}
	mediaType, _, _ := mime.ParseMediaType(v.ContentType)
	if isText(mediaType) && utf8.Valid(data) {
		out.Text = string(data)
		return nil, out, nil
	}
	out.Base64 = base64.StdEncoding.EncodeToString(data)
	if strings.HasPrefix(mediaType, "image/") && mediaType != "image/svg+xml" && len(data) <= maxInlineImage {
		summary, _ := json.Marshal(map[string]any{"file": f, "version": v.Number, "content_type": v.ContentType, "size": v.Size})
		return &mcp.CallToolResult{Content: []mcp.Content{
			&mcp.TextContent{Text: string(summary)},
			&mcp.ImageContent{Data: data, MIMEType: mediaType},
		}}, out, nil
	}
	return nil, out, nil
}

func isText(mediaType string) bool {
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	switch mediaType {
	case "application/json", "application/xml", "application/javascript", "image/svg+xml", "application/x-yaml", "application/toml":
		return true
	}
	return strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml")
}

func (s *server) uploadURL(ctx context.Context, in UploadURLInput) (uploadURLOutput, error) {
	ttl := time.Duration(clamp(in.ExpiresMinutes, 60, 1440)) * time.Minute
	link := files.UploadLinkInput{
		Namespace: in.Namespace, Name: in.Name, Password: in.Password, AllowedEmails: in.AllowedEmails,
		Client: client(ctx), ExpiresAt: time.Now().Add(ttl), ExpectedVersion: in.ExpectedVersion,
	}
	if in.File != "" {
		f, err := s.files.Resolve(ctx, in.File)
		if err != nil {
			return uploadURLOutput{}, err
		}
		link.FileID = f.ID
	}
	created, err := s.files.CreateUploadLink(ctx, link)
	if err != nil {
		return uploadURLOutput{}, err
	}
	u := s.files.BaseURL() + "/upload/" + s.auth.SignUpload(created.ID, ttl)
	return uploadURLOutput{
		UploadURL: u, SingleUse: true, ExpiresAt: created.ExpiresAt.Truncate(time.Second),
		URL: created.URL, Namespace: created.Namespace,
		Curl:               fmt.Sprintf("curl -sS --fail-with-body -F 'file=@./LOCAL_FILE' '%s'", u),
		MaxSingleRequestMB: 95,
		CurlChunked: fmt.Sprintf(`f=./LOCAL_FILE; u='%s'; d=$(mktemp -d) && split -b 90m "$f" "$d/p." && n=0 && `+
			`for p in "$d"/p.*; do n=$((n+1)); curl -sS --fail-with-body -X PUT --upload-file "$p" "$u?part=$n" >/dev/null || exit 1; done && `+
			`curl -sS --fail-with-body -X POST -G --data-urlencode "complete=$n" --data-urlencode "name=${f##*/}" "$u"; rm -rf "$d"`, u),
	}, nil
}

func (s *server) downloadURL(ctx context.Context, in DownloadURLInput) (downloadURLOutput, error) {
	f, err := s.files.Resolve(ctx, in.File)
	if err != nil {
		return downloadURLOutput{}, err
	}
	ttl := time.Duration(clamp(in.ExpiresMinutes, 60, 7*1440)) * time.Minute
	return downloadURLOutput{
		DownloadURL: s.files.BaseURL() + "/download/" + s.auth.SignDownload(auth.DownloadGrant{FileID: f.ID, Version: in.Version}, ttl),
		ExpiresAt:   time.Now().Add(ttl).UTC().Truncate(time.Second),
	}, nil
}

func clamp(v, def, max int) int {
	if v <= 0 {
		return def
	}
	return min(v, max)
}

func (s *server) get(ctx context.Context, in FileInput) (fileDetail, error) {
	f, err := s.files.Resolve(ctx, in.File)
	if err != nil {
		return fileDetail{}, err
	}
	versions, err := s.files.Versions(ctx, f.ID)
	return fileDetail{File: f, Versions: versions}, err
}

func (s *server) list(ctx context.Context, in ListInput) (listOutput, error) {
	list, err := s.files.List(ctx, files.ListOptions{Namespace: in.Namespace, Query: in.Query, Deleted: in.Deleted, Limit: in.Limit, Offset: in.Offset})
	if list == nil {
		list = []files.File{}
	}
	return listOutput{Files: list}, err
}

func (s *server) versions(ctx context.Context, in FileInput) (versionsOutput, error) {
	f, err := s.files.Resolve(ctx, in.File)
	if err != nil {
		return versionsOutput{}, err
	}
	v, err := s.files.Versions(ctx, f.ID)
	return versionsOutput{Versions: v}, err
}

func (s *server) withFile(ctx context.Context, ref string, fn func(files.File) (files.File, error)) (files.File, error) {
	f, err := s.files.Resolve(ctx, ref)
	if err != nil {
		return files.File{}, err
	}
	return fn(f)
}

func (s *server) rollback(ctx context.Context, in RollbackInput) (files.File, error) {
	return s.withFile(ctx, in.File, func(f files.File) (files.File, error) { return s.files.Rollback(ctx, f.ID, in.Version, client(ctx)) })
}

func (s *server) rename(ctx context.Context, in RenameInput) (files.File, error) {
	return s.withFile(ctx, in.File, func(f files.File) (files.File, error) { return s.files.Rename(ctx, f.ID, in.NewName) })
}

func (s *server) delete(ctx context.Context, in FileInput) (files.File, error) {
	return s.withFile(ctx, in.File, func(f files.File) (files.File, error) { return s.files.Delete(ctx, f.ID) })
}

func (s *server) restore(ctx context.Context, in FileInput) (files.File, error) {
	return s.withFile(ctx, in.File, func(f files.File) (files.File, error) { return s.files.Restore(ctx, f.ID) })
}

func (s *server) setPassword(ctx context.Context, in PasswordInput) (files.File, error) {
	if in.Password == "" {
		return files.File{}, errors.New("password is required; use remove_password to clear it")
	}
	return s.withFile(ctx, in.File, func(f files.File) (files.File, error) { return s.files.SetPassword(ctx, f.ID, in.Password) })
}

func (s *server) removePassword(ctx context.Context, in FileInput) (files.File, error) {
	return s.withFile(ctx, in.File, func(f files.File) (files.File, error) { return s.files.SetPassword(ctx, f.ID, "") })
}

func (s *server) setAllowedEmails(ctx context.Context, in EmailsInput) (files.File, error) {
	return s.withFile(ctx, in.File, func(f files.File) (files.File, error) { return s.files.SetAllowedEmails(ctx, f.ID, in.Emails) })
}

func (s *server) accessLog(ctx context.Context, in AccessLogInput) (accessLogOutput, error) {
	q := files.AccessQuery{Event: in.Event, Search: in.Search, Before: in.Before, Limit: in.Limit}
	if id, err := uuid.Parse(strings.TrimSpace(in.File)); err == nil {
		q.FileID = id.String() // works for purged files too
	} else if in.File != "" {
		f, err := s.files.Resolve(ctx, in.File)
		if err != nil {
			return accessLogOutput{}, err
		}
		q.FileID = f.ID
	}
	events, err := s.files.ListAccess(ctx, q)
	if events == nil {
		events = []files.AccessEvent{}
	}
	return accessLogOutput{Events: events}, err
}

func (s *server) purge(ctx context.Context, in PurgeInput) (okOutput, error) {
	if !in.Confirm {
		return okOutput{}, errors.New("purge_file is irreversible; call again with confirm=true (or use delete_file, which can be undone)")
	}
	f, err := s.files.Resolve(ctx, in.File)
	if err != nil {
		return okOutput{}, err
	}
	if err := s.files.PurgeFile(ctx, f.ID); err != nil {
		return okOutput{}, err
	}
	return okOutput{OK: true}, nil
}

func (s *server) stats(ctx context.Context, _ Empty) (statsOutput, error) {
	st, err := s.files.Stats(ctx)
	return statsOutput{Stats: st, RetentionDays: int(s.files.Retention().Hours() / 24), MaxUploadBytes: s.files.MaxBytes(), BaseURL: s.files.BaseURL()}, err
}
