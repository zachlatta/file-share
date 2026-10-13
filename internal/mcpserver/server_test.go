package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zachlatta/file-share/internal/auth"
	"github.com/zachlatta/file-share/internal/blob"
	"github.com/zachlatta/file-share/internal/fetch"
	"github.com/zachlatta/file-share/internal/files"
	"github.com/zachlatta/file-share/internal/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	svc, err := files.Open(context.Background(), files.Config{
		DatabaseURL: pgtest.New(t), Blobs: blob.NewMemory(), BaseURL: "https://files.example.com",
		Retention: 30 * 24 * time.Hour, MaxBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	a := auth.NewService(auth.Config{Secret: "mcp-test-secret-0123456789-abcdef", BaseURL: "https://files.example.com"})
	server := New(Config{Files: svc, Auth: a, Fetcher: fetch.New(fetch.Options{AllowPrivate: true}), Version: "test"})
	st, ct := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Run(ctx, st) }()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func call(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := s.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	var out []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			out = append(out, tc.Text)
		}
	}
	return strings.Join(out, "\n")
}

func ok(t *testing.T, res *mcp.CallToolResult, into any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", text(res))
	}
	reflect.ValueOf(into).Elem().SetZero() // callers reuse targets
	data, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
}

func TestCatalog(t *testing.T) {
	s := connect(t)
	tools, err := s.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if tool.Description == "" || tool.Annotations == nil {
			t.Errorf("%s lacks description or annotations", tool.Name)
		}
	}
	for _, want := range []string{"upload_file", "create_upload_url", "replace_file", "read_file", "create_download_url",
		"get_file", "list_files", "list_versions", "rollback_file", "rename_file", "delete_file", "restore_file",
		"purge_file", "set_password", "remove_password", "get_stats"} {
		if !slices.Contains(names, want) {
			t.Errorf("missing tool %s", want)
		}
	}
	if !strings.Contains(s.InitializeResult().Instructions, "30 days") {
		t.Errorf("instructions should state retention: %q", s.InitializeResult().Instructions)
	}
}

func TestUploadReadReplaceRollback(t *testing.T) {
	s := connect(t)
	var f files.File
	ok(t, call(t, s, "upload_file", map[string]any{"name": "notes.md", "content_text": "# v1"}), &f)
	if !strings.HasPrefix(f.URL, "https://files.example.com/") || f.Version != 1 {
		t.Fatalf("upload = %+v", f)
	}
	// Second file into the same namespace, base64.
	var g files.File
	ok(t, call(t, s, "upload_file", map[string]any{"name": "img/dot.png", "namespace": f.Namespace, "content_base64": base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nfake"))}), &g)
	if g.Namespace != f.Namespace || g.ContentType != "image/png" {
		t.Fatalf("second upload = %+v", g)
	}
	// Exactly one content source.
	if res := call(t, s, "upload_file", map[string]any{"name": "x.txt"}); !res.IsError {
		t.Fatal("upload without content accepted")
	}
	if res := call(t, s, "upload_file", map[string]any{"name": "x.txt", "content_text": "a", "content_base64": "YQ=="}); !res.IsError {
		t.Fatal("upload with two sources accepted")
	}

	ok(t, call(t, s, "replace_file", map[string]any{"file": f.URL, "content_text": "# v2"}), &f)
	if f.Version != 2 {
		t.Fatalf("replace = %+v", f)
	}
	var read readOutput
	ok(t, call(t, s, "read_file", map[string]any{"file": f.ID, "version": 1}), &read)
	if read.Text != "# v1" || read.Version != 1 {
		t.Fatalf("read v1 = %+v", read)
	}
	ok(t, call(t, s, "rollback_file", map[string]any{"file": f.ID, "version": 1}), &f)
	ok(t, call(t, s, "read_file", map[string]any{"file": f.URL}), &read)
	if f.Version != 3 || read.Text != "# v1" {
		t.Fatalf("after rollback: %+v %+v", f, read)
	}
	var versions versionsOutput
	ok(t, call(t, s, "list_versions", map[string]any{"file": f.ID}), &versions)
	if len(versions.Versions) != 3 {
		t.Fatalf("versions = %+v", versions)
	}
	// Binary reads return base64; images also as image content.
	res := call(t, s, "read_file", map[string]any{"file": g.ID})
	ok(t, res, &read)
	if read.Base64 == "" || read.Text != "" {
		t.Fatalf("binary read = %+v", read)
	}
	hasImage := false
	for _, c := range res.Content {
		if _, isImage := c.(*mcp.ImageContent); isImage {
			hasImage = true
		}
	}
	if !hasImage {
		t.Fatal("image read lacks image content")
	}
}

func TestDeleteRestorePurgeAndPasswords(t *testing.T) {
	s := connect(t)
	var f files.File
	ok(t, call(t, s, "upload_file", map[string]any{"name": "a.txt", "content_text": "a", "password": "pw1"}), &f)
	if !f.HasPassword {
		t.Fatal("password not set on upload")
	}
	ok(t, call(t, s, "remove_password", map[string]any{"file": f.ID}), &f)
	if f.HasPassword {
		t.Fatal("password not removed")
	}
	ok(t, call(t, s, "set_password", map[string]any{"file": f.ID, "password": "pw2"}), &f)
	if !f.HasPassword {
		t.Fatal("password not set")
	}
	ok(t, call(t, s, "delete_file", map[string]any{"file": f.URL}), &f)
	if f.DeletedAt == nil || f.PurgeAt == nil {
		t.Fatalf("delete = %+v", f)
	}
	var list listOutput
	ok(t, call(t, s, "list_files", map[string]any{"deleted": true}), &list)
	if len(list.Files) != 1 {
		t.Fatalf("trash = %+v", list)
	}
	ok(t, call(t, s, "restore_file", map[string]any{"file": f.ID}), &f)
	if f.DeletedAt != nil {
		t.Fatal("not restored")
	}
	ok(t, call(t, s, "rename_file", map[string]any{"file": f.ID, "new_name": "b.txt"}), &f)
	if f.Name != "b.txt" {
		t.Fatal("not renamed")
	}
	if res := call(t, s, "purge_file", map[string]any{"file": f.ID}); !res.IsError {
		t.Fatal("purge without confirm accepted")
	}
	var done okOutput
	ok(t, call(t, s, "purge_file", map[string]any{"file": f.ID, "confirm": true}), &done)
	if res := call(t, s, "get_file", map[string]any{"file": f.ID}); !res.IsError {
		t.Fatal("purged file still exists")
	}
}

func TestSignedURLsAndSourceURL(t *testing.T) {
	s := connect(t)
	var up uploadURLOutput
	ok(t, call(t, s, "create_upload_url", map[string]any{"name": "big.mov"}), &up)
	if !strings.HasPrefix(up.UploadURL, "https://files.example.com/upload/") || !strings.Contains(up.Curl, "--upload-file") {
		t.Fatalf("upload url = %+v", up)
	}
	var f files.File
	ok(t, call(t, s, "upload_file", map[string]any{"name": "a.txt", "content_text": "a"}), &f)
	var down downloadURLOutput
	ok(t, call(t, s, "create_download_url", map[string]any{"file": f.ID}), &down)
	if !strings.HasPrefix(down.DownloadURL, "https://files.example.com/download/") {
		t.Fatalf("download url = %+v", down)
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("from the web")) }))
	defer origin.Close()
	var g files.File
	ok(t, call(t, s, "upload_file", map[string]any{"source_url": origin.URL + "/page.txt"}), &g)
	var read readOutput
	ok(t, call(t, s, "read_file", map[string]any{"file": g.ID}), &read)
	if g.Name != "page.txt" || read.Text != "from the web" {
		t.Fatalf("source url upload: %+v %+v", g, read)
	}
	var st statsOutput
	ok(t, call(t, s, "get_stats", nil), &st)
	if st.Files != 2 || st.RetentionDays != 30 {
		t.Fatalf("stats = %+v", st)
	}
}
