package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
)

func newFakeS3(t *testing.T) *S3 {
	t.Helper()
	backend := s3mem.New()
	server := httptest.NewServer(gofakes3.New(backend).Server())
	t.Cleanup(server.Close)
	store, err := NewS3(S3Config{
		Endpoint:  server.URL,
		AccessKey: "test",
		SecretKey: "test",
		Bucket:    "files",
		Region:    "zrl-home",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.client.MakeBucket(context.Background(), "files", minioMakeBucketOptions()); err != nil {
		t.Fatal(err)
	}
	return store
}

func stores(t *testing.T) map[string]Store {
	all := map[string]Store{"memory": NewMemory(), "s3": newFakeS3(t)}
	// Opt-in: run the contract against a real S3-compatible service too.
	if endpoint := os.Getenv("FILE_SHARE_TEST_S3_ENDPOINT"); endpoint != "" {
		real, err := NewS3(S3Config{
			Endpoint: endpoint, Bucket: os.Getenv("FILE_SHARE_TEST_S3_BUCKET"), Region: os.Getenv("FILE_SHARE_TEST_S3_REGION"),
			AccessKey: os.Getenv("FILE_SHARE_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("FILE_SHARE_TEST_S3_SECRET_KEY"),
		})
		if err != nil {
			t.Fatal(err)
		}
		all["real-s3"] = real
	}
	return all
}

func TestStoreContract(t *testing.T) {
	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			prefix := "contract-test/" + strings.ToLower(rand.Text()) + "/"
			payload := []byte("hello, world: a fairly ordinary payload")
			if err := store.Put(ctx, prefix+"a", bytes.NewReader(payload), int64(len(payload)), "text/plain"); err != nil {
				t.Fatalf("put: %v", err)
			}
			// Unknown size streams too.
			if err := store.Put(ctx, prefix+"b", strings.NewReader("streamed"), -1, "application/octet-stream"); err != nil {
				t.Fatalf("put unknown size: %v", err)
			}
			obj, err := store.Get(ctx, prefix+"a")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			// Objects must be seekable for HTTP range requests.
			if _, err := obj.Seek(7, io.SeekStart); err != nil {
				t.Fatalf("seek: %v", err)
			}
			rest, _ := io.ReadAll(obj)
			_ = obj.Close()
			if string(rest) != "world: a fairly ordinary payload" {
				t.Fatalf("read after seek = %q", rest)
			}
			obj, err = store.Get(ctx, prefix+"b")
			if err != nil {
				t.Fatal(err)
			}
			all, _ := io.ReadAll(obj)
			_ = obj.Close()
			if string(all) != "streamed" {
				t.Fatalf("streamed = %q", all)
			}

			t.Cleanup(func() { _ = store.Delete(context.Background(), prefix+"b") })
			if err := store.Delete(ctx, prefix+"a"); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if _, err := store.Get(ctx, prefix+"a"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("get deleted: %v", err)
			}
			// Deleting a missing key is not an error.
			if err := store.Delete(ctx, prefix+"never"); err != nil {
				t.Fatalf("delete missing: %v", err)
			}
			if err := store.Ping(ctx); err != nil {
				t.Fatalf("ping: %v", err)
			}
		})
	}
}
