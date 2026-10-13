// Package blob stores immutable file bytes. Every file version is written
// once under its own random key and never modified, so version history is a
// property of the metadata database, not of the object store (Garage has no
// S3 object versioning).
package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var ErrNotFound = errors.New("blob not found")

// Object is a seekable reader, so HTTP range requests can be served directly.
type Object interface {
	io.ReadSeekCloser
}

type Store interface {
	// Put stores r under key. size may be -1 when unknown.
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	Get(ctx context.Context, key string) (Object, error)
	// Delete removes key; deleting a missing key succeeds.
	Delete(ctx context.Context, key string) error
	Ping(ctx context.Context) error
}

// Memory is an in-process Store for tests.
type Memory struct {
	mu   sync.Mutex
	data map[string][]byte
}

func NewMemory() *Memory { return &Memory{data: map[string][]byte{}} }

func (m *Memory) Put(_ context.Context, key string, r io.Reader, _ int64, _ string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = data
	return nil
}

func (m *Memory) Get(_ context.Context, key string) (Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.data[key]
	if !ok {
		return nil, ErrNotFound
	}
	return nopCloser{bytes.NewReader(data)}, nil
}

func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *Memory) Ping(context.Context) error { return nil }

// Keys lists stored keys (test helper).
func (m *Memory) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

type S3Config struct {
	// Endpoint is a URL such as http://garage.internal:3900 (scheme selects TLS).
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	Region    string
}

// S3 stores blobs in an S3-compatible bucket using path-style addressing,
// which Garage requires.
type S3 struct {
	client *minio.Client
	bucket string
}

func NewS3(cfg S3Config) (*S3, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("S3 endpoint %q must be an http(s) URL", cfg.Endpoint)
	}
	client, err := minio.New(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure:       u.Scheme == "https",
		Region:       cfg.Region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		return nil, err
	}
	return &S3{client: client, bucket: cfg.Bucket}, nil
}

func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	// Unsigned payloads avoid aws-chunked streaming signatures, which some
	// S3-compatible servers (and test fakes) handle poorly over plain HTTP.
	opts := minio.PutObjectOptions{ContentType: contentType, DisableContentSha256: true}
	if size < 0 {
		opts.PartSize = 16 << 20
	}
	_, err := s.client.PutObject(ctx, s.bucket, key, r, size, opts)
	return err
}

func (s *S3) Get(ctx context.Context, key string) (Object, error) {
	// GetObject is lazy; Stat forces the request so a missing key errors here.
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return obj, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
	if err != nil && minio.ToErrorResponse(err).Code == "NoSuchKey" {
		return nil
	}
	return err
}

func (s *S3) Ping(ctx context.Context) error {
	ok, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("bucket %q does not exist", s.bucket)
	}
	return nil
}

func minioMakeBucketOptions() minio.MakeBucketOptions { return minio.MakeBucketOptions{} }
