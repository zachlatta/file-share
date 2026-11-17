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
			// Empty objects store and read back, at known and unknown size.
			for key, size := range map[string]int64{"empty": 0, "empty-streamed": -1} {
				if err := store.Put(ctx, prefix+key, strings.NewReader(""), size, "text/plain"); err != nil {
					t.Fatalf("put %s: %v", key, err)
				}
				obj, err := store.Get(ctx, prefix+key)
				if err != nil {
					t.Fatalf("get %s: %v", key, err)
				}
				data, err := io.ReadAll(obj)
				_ = obj.Close()
				if err != nil || len(data) != 0 {
					t.Fatalf("read %s = %q, %v", key, data, err)
				}
				if err := store.Delete(ctx, prefix+key); err != nil {
					t.Fatalf("delete %s: %v", key, err)
				}
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
			// List finds objects under a prefix, with modification times.
			list, err := store.List(ctx, prefix)
			if err != nil || len(list) != 1 || list[0].Key != prefix+"b" || list[0].Modified.IsZero() {
				t.Fatalf("list = %+v, %v", list, err)
			}
			if other, _ := store.List(ctx, prefix+"zzz"); len(other) != 0 {
				t.Fatalf("list of empty prefix = %+v", other)
			}
			if err := store.Ping(ctx); err != nil {
				t.Fatalf("ping: %v", err)
			}
		})
	}
}

// Stat reports an object's size without reading it, and Copy duplicates an
// object server-side, which is how staged uploads reach their content key.
func TestStoreStatAndCopy(t *testing.T) {
	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			prefix := "contract-test/" + strings.ToLower(rand.Text()) + "/"
			t.Cleanup(func() {
				for _, k := range []string{"src", "dst", "empty", "empty-copy"} {
					_ = store.Delete(context.Background(), prefix+k)
				}
			})
			payload := []byte("bytes that get copied")
			if err := store.Put(ctx, prefix+"src", bytes.NewReader(payload), int64(len(payload)), "text/plain"); err != nil {
				t.Fatal(err)
			}
			info, err := store.Stat(ctx, prefix+"src")
			if err != nil || info.Key != prefix+"src" || info.Size != int64(len(payload)) || info.Modified.IsZero() {
				t.Fatalf("stat = %+v, %v", info, err)
			}
			if _, err := store.Stat(ctx, prefix+"missing"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("stat missing: %v", err)
			}
			if err := store.Copy(ctx, prefix+"src", prefix+"dst"); err != nil {
				t.Fatalf("copy: %v", err)
			}
			obj, err := store.Get(ctx, prefix+"dst")
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(obj)
			_ = obj.Close()
			if !bytes.Equal(got, payload) {
				t.Fatalf("copied = %q", got)
			}
			if err := store.Copy(ctx, prefix+"missing", prefix+"never"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("copy missing: %v", err)
			}
			if err := store.Put(ctx, prefix+"empty", strings.NewReader(""), 0, "text/plain"); err != nil {
				t.Fatal(err)
			}
			if err := store.Copy(ctx, prefix+"empty", prefix+"empty-copy"); err != nil {
				t.Fatalf("copy empty: %v", err)
			}
			if info, err := store.Stat(ctx, prefix+"empty-copy"); err != nil || info.Size != 0 {
				t.Fatalf("stat empty copy = %+v, %v", info, err)
			}
		})
	}
}

// Objects over the single-request copy limit (5 GiB on S3) are copied with a
// multipart copy. The limit is lowered here so a small object takes that
// path; gofakes3 has no UploadPartCopy, so this runs against a real store.
func TestS3MultipartCopy(t *testing.T) {
	store, ok := stores(t)["real-s3"].(*S3)
	if !ok {
		t.Skip("set FILE_SHARE_TEST_S3_ENDPOINT to test multipart copy against a real store")
	}
	store.copyLimit = 1
	ctx := context.Background()
	prefix := "contract-test/" + strings.ToLower(rand.Text()) + "/"
	t.Cleanup(func() {
		_ = store.Delete(context.Background(), prefix+"src")
		_ = store.Delete(context.Background(), prefix+"dst")
	})
	payload := bytes.Repeat([]byte("multipart copy "), 1000)
	if err := store.Put(ctx, prefix+"src", bytes.NewReader(payload), int64(len(payload)), "text/plain"); err != nil {
		t.Fatal(err)
	}
	if err := store.Copy(ctx, prefix+"src", prefix+"dst"); err != nil {
		t.Fatalf("multipart copy: %v", err)
	}
	obj, err := store.Get(ctx, prefix+"dst")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(obj)
	_ = obj.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("copied %d bytes, want %d", len(got), len(payload))
	}
}

// ReadOnly passes reads through and refuses every write, so a dry run cannot
// change the store.
func TestReadOnly(t *testing.T) {
	ctx := context.Background()
	mem := NewMemory()
	if err := mem.Put(ctx, "a", strings.NewReader("x"), 1, "text/plain"); err != nil {
		t.Fatal(err)
	}
	ro := ReadOnly(mem)
	if _, err := ro.Stat(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if obj, err := ro.Get(ctx, "a"); err != nil {
		t.Fatal(err)
	} else {
		_ = obj.Close()
	}
	if list, err := ro.List(ctx, ""); err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	for name, err := range map[string]error{
		"put":    ro.Put(ctx, "b", strings.NewReader("x"), 1, "text/plain"),
		"copy":   ro.Copy(ctx, "a", "b"),
		"delete": ro.Delete(ctx, "a"),
	} {
		if !errors.Is(err, ErrReadOnly) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if keys := mem.Keys(); len(keys) != 1 {
		t.Fatalf("keys = %v", keys)
	}
}
