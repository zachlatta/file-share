package fetch

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBlocksPrivateAddressesByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("internal")) }))
	defer server.Close()
	_, err := New(Options{}).Get(context.Background(), server.URL+"/x.txt")
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("loopback fetch: %v", err)
	}
	for _, raw := range []string{"http://100.100.1.1:3900/", "http://10.0.0.1/", "http://169.254.169.254/latest", "http://[::1]/"} {
		if _, err := New(Options{}).Get(context.Background(), raw); err == nil {
			t.Errorf("%s allowed", raw)
		}
	}
}

func TestRejectsNonHTTP(t *testing.T) {
	for _, raw := range []string{"file:///etc/passwd", "ftp://example.com/x", "not a url"} {
		if _, err := New(Options{}).Get(context.Background(), raw); err == nil {
			t.Errorf("%s allowed", raw)
		}
	}
}

func TestFetchesAndNamesFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dl":
			w.Header().Set("Content-Disposition", `attachment; filename="report final.pdf"`)
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write([]byte("%PDF"))
		case "/missing":
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte("hello"))
		}
	}))
	defer server.Close()
	f := New(Options{AllowPrivate: true})
	res, err := f.Get(context.Background(), server.URL+"/dir/cat.png?x=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.Filename != "cat.png" || string(body) != "hello" {
		t.Fatalf("res = %+v %q", res, body)
	}
	res, err = f.Get(context.Background(), server.URL+"/dl")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Filename != "report final.pdf" || res.ContentType != "application/pdf" {
		t.Fatalf("res = %+v", res)
	}
	if _, err := f.Get(context.Background(), server.URL+"/missing"); err == nil {
		t.Fatal("404 accepted")
	}
	res, _ = f.Get(context.Background(), server.URL+"/")
	res.Body.Close()
	if res.Filename != "download" {
		t.Fatalf("fallback filename = %q", res.Filename)
	}
}
