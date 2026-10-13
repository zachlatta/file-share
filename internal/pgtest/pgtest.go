// Package pgtest gives tests a fresh, empty PostgreSQL database.
//
// With FILE_SHARE_TEST_DATABASE_URL set (CI), each test gets a new database
// on that server. Otherwise a throwaway cluster is started with the local
// initdb/pg_ctl binaries. If neither is available the test is skipped, unless
// FILE_SHARE_REQUIRE_POSTGRES=1, in which case it fails.
package pgtest

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/rand"

	"github.com/jackc/pgx/v5"
)

var (
	once      sync.Once
	serverURL string
	setupErr  error
	stopFn    func()
)

// Main runs the tests and then stops any cluster this package started.
func Main(m interface{ Run() int }) {
	code := m.Run()
	if stopFn != nil {
		stopFn()
	}
	os.Exit(code)
}

// New returns the URL of a new empty database that is dropped after the test.
func New(t testing.TB) string {
	t.Helper()
	once.Do(func() {
		if env := os.Getenv("FILE_SHARE_TEST_DATABASE_URL"); env != "" {
			serverURL = env
			return
		}
		serverURL, stopFn, setupErr = startCluster()
	})
	if setupErr != nil || serverURL == "" {
		if os.Getenv("FILE_SHARE_REQUIRE_POSTGRES") == "1" {
			t.Fatalf("postgres unavailable: %v", setupErr)
		}
		t.Skipf("postgres unavailable: %v", setupErr)
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, serverURL)
	if err != nil {
		t.Fatalf("connect to test postgres: %v", err)
	}
	defer admin.Close(ctx)
	name := "t_" + strings.ToLower(rand.Text())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		conn, err := pgx.Connect(context.Background(), serverURL)
		if err != nil {
			return
		}
		defer conn.Close(context.Background())
		_, _ = conn.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, _ := url.Parse(serverURL)
	u.Path = "/" + name
	return u.String()
}

func findBinDir() (string, error) {
	candidates := []string{}
	if p, err := exec.LookPath("postgres"); err == nil {
		candidates = append(candidates, filepath.Dir(p))
	}
	for _, pattern := range []string{"/opt/homebrew/opt/postgresql*/bin", "/usr/local/opt/postgresql*/bin", "/usr/lib/postgresql/*/bin"} {
		matches, _ := filepath.Glob(pattern)
		candidates = append(candidates, matches...)
	}
	for _, dir := range candidates {
		dir, _ = filepath.EvalSymlinks(dir)
		ok := true
		for _, bin := range []string{"initdb", "pg_ctl", "postgres"} {
			if _, err := os.Stat(filepath.Join(dir, bin)); err != nil {
				ok = false
			}
		}
		if ok {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no initdb/pg_ctl/postgres found")
}

func startCluster() (string, func(), error) {
	bin, err := findBinDir()
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "file-share-pg-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	data := filepath.Join(dir, "data")
	if out, err := exec.Command(filepath.Join(bin, "initdb"), "-D", data, "-U", "postgres", "-A", "trust", "--no-sync").CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("initdb: %v: %s", err, out)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cleanup()
		return "", nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	opts := fmt.Sprintf("-p %d -k %s -c listen_addresses=127.0.0.1 -c fsync=off -c synchronous_commit=off -c full_page_writes=off", port, dir)
	if out, err := exec.Command(filepath.Join(bin, "pg_ctl"), "-D", data, "-o", opts, "-l", filepath.Join(dir, "log"), "-w", "-t", "30", "start").CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("pg_ctl start: %v: %s", err, out)
	}
	stop := func() {
		_ = exec.Command(filepath.Join(bin, "pg_ctl"), "-D", data, "-m", "immediate", "stop").Run()
		cleanup()
	}
	u := fmt.Sprintf("postgres://postgres@127.0.0.1:%d/postgres?sslmode=disable", port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, u)
	if err != nil {
		stop()
		return "", nil, err
	}
	_ = conn.Close(ctx)
	return u, stop, nil
}
