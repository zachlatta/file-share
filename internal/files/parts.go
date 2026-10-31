package files

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/zachlatta/file-share/internal/blob"
)

// Chunked uploads exist because proxies in front of the server cap request
// bodies (Cloudflare rejects bodies over 100 MB) and time out slow
// single-stream uploads or long-running completions. Each part is stored as a
// temporary object; completing streams the parts in a detached background job
// through the normal upload path (returning ErrAssembling if a request wait
// window elapses first so callers can poll) and then deletes them. Parts that
// are never completed are purged after partTTL.

const (
	maxParts = 10000
	partTTL  = 24 * time.Hour
)

type completion struct {
	done   chan struct{}
	file   File
	err    error
	doneAt time.Time
}

func (s *Service) sweepCompletingLocked(now time.Time) {
	for k, c := range s.completing {
		if !c.doneAt.IsZero() && now.Sub(c.doneAt) >= s.completeResultTTL {
			delete(s.completing, k)
		}
	}
}

func (s *Service) hasCompleting(uploadKey string) bool {
	s.completingMu.Lock()
	defer s.completingMu.Unlock()
	s.sweepCompletingLocked(s.now())
	_, ok := s.completing[uploadKey]
	return ok
}

var uploadKeyPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func partKey(uploadKey string, n int) string { return fmt.Sprintf("uploads/%s/%05d", uploadKey, n) }

// PutPart stores part n (1-based) of the chunked upload uploadKey (32 hex
// characters) and returns its size. Re-sending a part replaces it.
func (s *Service) PutPart(ctx context.Context, uploadKey string, n int, body io.Reader, size int64) (int64, error) {
	if !uploadKeyPattern.MatchString(uploadKey) {
		return 0, fmt.Errorf("%w: bad upload key", ErrInvalid)
	}
	if n < 1 || n > maxParts {
		return 0, fmt.Errorf("%w: part must be between 1 and %d", ErrInvalid, maxParts)
	}
	if s.maxBytes > 0 && size > s.maxBytes {
		return 0, ErrTooLarge
	}
	counter := &countingReader{r: body, limit: s.maxBytes}
	if err := s.blobs.Put(ctx, partKey(uploadKey, n), counter, size, "application/octet-stream"); err != nil || counter.exceeded {
		_ = s.blobs.Delete(context.WithoutCancel(ctx), partKey(uploadKey, n))
		if counter.exceeded {
			return 0, ErrTooLarge
		}
		return 0, fmt.Errorf("store part: %w", err)
	}
	return counter.n, nil
}

// CompleteParts opens parts 1..parts of uploadKey as one stream and passes it
// to fn (normally Upload, Replace or UploadWithLink) in a detached background
// context. If assembly takes longer than CompleteWait, CompleteParts returns
// ErrAssembling while the background job continues; subsequent calls for the
// same uploadKey wait on the running job or return its finished result. The
// parts are deleted only if fn succeeds, so a failed completion can be retried.
func (s *Service) CompleteParts(ctx context.Context, uploadKey string, parts int, fn func(context.Context, io.Reader) (File, error)) (File, error) {
	if !uploadKeyPattern.MatchString(uploadKey) {
		return File{}, fmt.Errorf("%w: bad upload key", ErrInvalid)
	}
	if parts < 1 || parts > maxParts {
		return File{}, fmt.Errorf("%w: parts must be between 1 and %d", ErrInvalid, maxParts)
	}
	s.completingMu.Lock()
	s.sweepCompletingLocked(s.now())
	job, exists := s.completing[uploadKey]
	if !exists {
		job = &completion{done: make(chan struct{})}
		s.completing[uploadKey] = job
		s.completingWG.Add(1)
	}
	s.completingMu.Unlock()

	if !exists {
		go s.runCompletion(ctx, uploadKey, parts, fn, job)
	}

	select {
	case <-job.done:
		return job.file, job.err
	default:
	}
	timer := time.NewTimer(s.completeWait)
	defer timer.Stop()
	select {
	case <-job.done:
		return job.file, job.err
	case <-timer.C:
		return File{}, ErrAssembling
	case <-ctx.Done():
		return File{}, ctx.Err()
	}
}

func (s *Service) runCompletion(reqCtx context.Context, uploadKey string, parts int, fn func(context.Context, io.Reader) (File, error), job *completion) {
	defer s.completingWG.Done()
	bgCtx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), s.completeTimeout)
	stop := context.AfterFunc(s.closeCtx, cancel)
	defer func() {
		stop()
		cancel()
	}()

	existing, err := s.blobs.List(bgCtx, "uploads/"+uploadKey+"/")
	if err == nil {
		have := map[string]bool{}
		for _, obj := range existing {
			have[obj.Key] = true
		}
		for n := 1; n <= parts; n++ {
			if !have[partKey(uploadKey, n)] {
				err = fmt.Errorf("%w: part %d has not been uploaded", ErrInvalid, n)
				break
			}
		}
	}
	if err != nil {
		s.completingMu.Lock()
		job.err = err
		delete(s.completing, uploadKey)
		close(job.done)
		s.completingMu.Unlock()
		return
	}

	f, err := fn(bgCtx, &partReader{ctx: bgCtx, blobs: s.blobs, uploadKey: uploadKey, parts: parts})
	if err == nil {
		for _, obj := range existing {
			_ = s.blobs.Delete(bgCtx, obj.Key)
		}
	}
	s.completingMu.Lock()
	job.file, job.err = f, err
	job.doneAt = s.now()
	close(job.done)
	s.completingMu.Unlock()
}

// partReader reads the parts one after another, opening each lazily.
type partReader struct {
	ctx       context.Context
	blobs     blob.Store
	uploadKey string
	parts     int
	next      int
	current   blob.Object
}

func (p *partReader) Read(b []byte) (int, error) {
	for {
		if p.current == nil {
			if p.next >= p.parts {
				return 0, io.EOF
			}
			p.next++
			obj, err := p.blobs.Get(p.ctx, partKey(p.uploadKey, p.next))
			if err != nil {
				return 0, fmt.Errorf("open part %d: %w", p.next, err)
			}
			p.current = obj
		}
		n, err := p.current.Read(b)
		if errors.Is(err, io.EOF) {
			_ = p.current.Close()
			p.current = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

// purgeParts deletes parts of uploads abandoned for longer than partTTL.
func (s *Service) purgeParts(ctx context.Context) (int, error) {
	objects, err := s.blobs.List(ctx, "uploads/")
	if err != nil {
		return 0, err
	}
	cutoff := s.now().Add(-partTTL)
	deleted := 0
	var errs []error
	for _, obj := range objects {
		if obj.Modified.Before(cutoff) {
			if err := s.blobs.Delete(ctx, obj.Key); err != nil {
				errs = append(errs, err)
				continue
			}
			deleted++
		}
	}
	return deleted, errors.Join(errs...)
}
