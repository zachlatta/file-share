package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/zachlatta/file-share/internal/pgtest"
)

func TestUsageAndConfigErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"bogus"}, &out, &errOut); code != 2 {
		t.Fatalf("bogus command exit = %d", code)
	}
	t.Setenv("MCP_SECRET", "short")
	if code := run([]string{"serve"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "MCP_SECRET") {
		t.Fatalf("bad config: exit %d, %q", code, errOut.String())
	}
}

func TestLogsNeverContainTokensOrQueries(t *testing.T) {
	var logs bytes.Buffer
	h := logRequests(slog.New(slog.NewJSONHandler(&logs, nil)), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, target := range []string{"/upload/SECRETTOKEN", "/download/SECRETTOKEN", "/ns/file.txt?password=SECRETPW"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
	}
	if strings.Contains(logs.String(), "SECRET") {
		t.Fatalf("secret leaked into logs: %s", logs.String())
	}
}

func TestMain(m *testing.M) { pgtest.Main(m) }

// The blob migration commands run against the configured database and
// bucket and print a JSON report. Dry runs never write.
func TestBlobMigrationCommands(t *testing.T) {
	backend := s3mem.New()
	if err := backend.CreateBucket("files"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gofakes3.New(backend).Server())
	t.Cleanup(server.Close)
	t.Setenv("MCP_SECRET", strings.Repeat("s", 32))
	t.Setenv("DATABASE_URL", pgtest.New(t))
	t.Setenv("S3_ENDPOINT", server.URL)
	t.Setenv("S3_BUCKET", "files")
	t.Setenv("S3_ACCESS_KEY", "test")
	t.Setenv("S3_SECRET_KEY", "test")

	report := func(args ...string) map[string]any {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 0 {
			t.Fatalf("%v: exit %d, %s", args, code, errOut.String())
		}
		var rep map[string]any
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatalf("%v: %v in %q", args, err, out.String())
		}
		return rep
	}
	// The first real run creates the schema.
	if rep := report("migrate-blobs"); rep["dry_run"] != false || rep["legacy_objects"] != 0.0 {
		t.Fatalf("migrate-blobs = %v", rep)
	}
	if rep := report("migrate-blobs", "-dry-run", "-verify"); rep["dry_run"] != true {
		t.Fatalf("dry run = %v", rep)
	}
	if rep := report("cleanup-legacy-blobs"); rep["confirm"] != false {
		t.Fatalf("cleanup = %v", rep)
	}
	if rep := report("cleanup-legacy-blobs", "-confirm"); rep["confirm"] != true {
		t.Fatalf("cleanup -confirm = %v", rep)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"migrate-blobs", "-bogus"}, &out, &errOut); code != 2 {
		t.Fatalf("bad flag exit = %d", code)
	}
}
