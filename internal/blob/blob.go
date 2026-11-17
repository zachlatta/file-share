// Package blob stores immutable file bytes. Callers write each key once and
// never modify it, so version history is a property of the metadata
// database, not of the object store (Garage has no S3 object versioning).
package blob

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var (
	ErrNotFound = errors.New("blob not found")
	ErrReadOnly = errors.New("blob store is read-only")
)

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
	// List returns the objects whose keys start with prefix.
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)
	// Stat describes key without reading it, or returns ErrNotFound.
	Stat(ctx context.Context, key string) (ObjectInfo, error)
	// Copy duplicates src to dst inside the store, or returns ErrNotFound if
	// src is missing. Callers must make sure dst does not exist.
	Copy(ctx context.Context, src, dst string) error
	Ping(ctx context.Context) error
}

type ObjectInfo struct {
	Key      string
	Size     int64
	Modified time.Time
}

// Memory is an in-process Store for tests.
type Memory struct {
	mu       sync.Mutex
	data     map[string][]byte
	modified map[string]time.Time
	// Now stamps modification times; defaults to time.Now.
	Now func() time.Time
}

func NewMemory() *Memory {
	return &Memory{data: map[string][]byte{}, modified: map[string]time.Time{}, Now: time.Now}
}

func (m *Memory) Put(_ context.Context, key string, r io.Reader, _ int64, _ string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = data
	m.modified[key] = m.Now()
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
	delete(m.modified, key)
	return nil
}

func (m *Memory) List(_ context.Context, prefix string) ([]ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ObjectInfo
	for k, v := range m.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, ObjectInfo{Key: k, Size: int64(len(v)), Modified: m.modified[k]})
		}
	}
	return out, nil
}

func (m *Memory) Stat(_ context.Context, key string) (ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.data[key]
	if !ok {
		return ObjectInfo{}, ErrNotFound
	}
	return ObjectInfo{Key: key, Size: int64(len(data)), Modified: m.modified[key]}, nil
}

func (m *Memory) Copy(_ context.Context, src, dst string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.data[src]
	if !ok {
		return ErrNotFound
	}
	m.data[dst] = bytes.Clone(data)
	m.modified[dst] = m.Now()
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

// ReadOnly wraps s so that reads pass through and writes fail with
// ErrReadOnly.
func ReadOnly(s Store) Store { return readOnly{s} }

type readOnly struct{ Store }

func (readOnly) Put(context.Context, string, io.Reader, int64, string) error { return ErrReadOnly }
func (readOnly) Copy(context.Context, string, string) error                  { return ErrReadOnly }
func (readOnly) Delete(context.Context, string) error                        { return ErrReadOnly }

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
	// copyLimit is the largest object CopyObject handles in one request;
	// larger objects use a multipart copy.
	copyLimit int64
}

// maxSingleCopy is S3's limit for a single-request CopyObject.
const maxSingleCopy = 5 << 30

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
	return &S3{client: client, bucket: cfg.Bucket, copyLimit: maxSingleCopy}, nil
}

func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	// Unsigned payloads avoid aws-chunked streaming signatures, which some
	// S3-compatible servers (and test fakes) handle poorly over plain HTTP.
	opts := minio.PutObjectOptions{ContentType: contentType, DisableContentSha256: true}
	if size < 0 {
		// An empty stream of unknown length would go out as a part with no
		// Content-Length, which Garage ("Empty body") and gofakes3 refuse; store
		// it as a known empty object.
		buffered := bufio.NewReader(r)
		if _, err := buffered.Peek(1); errors.Is(err, io.EOF) {
			size = 0
		} else if err != nil {
			return err
		}
		r = buffered
	}
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

func (s *S3) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var out []ObjectInfo
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		out = append(out, ObjectInfo{Key: obj.Key, Size: obj.Size, Modified: obj.LastModified})
	}
	return out, nil
}

func (s *S3) Stat(ctx context.Context, key string) (ObjectInfo, error) {
	info, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return ObjectInfo{}, ErrNotFound
		}
		return ObjectInfo{}, err
	}
	return ObjectInfo{Key: key, Size: info.Size, Modified: info.LastModified}, nil
}

func (s *S3) Copy(ctx context.Context, src, dst string) error {
	info, err := s.Stat(ctx, src)
	if err != nil {
		return err
	}
	srcOpts := minio.CopySrcOptions{Bucket: s.bucket, Object: src}
	dstOpts := minio.CopyDestOptions{Bucket: s.bucket, Object: dst}
	if info.Size <= s.copyLimit {
		_, err = s.client.CopyObject(ctx, dstOpts, srcOpts)
	} else {
		// UploadPartCopy in parts of at most 5 GiB each.
		_, err = s.client.ComposeObject(ctx, dstOpts, srcOpts)
	}
	if err != nil && isNotFound(err) {
		return ErrNotFound
	}
	return err
}

func isNotFound(err error) bool {
	code := minio.ToErrorResponse(err).Code
	return code == "NoSuchKey" || code == "NotFound"
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
