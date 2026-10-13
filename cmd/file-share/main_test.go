package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
