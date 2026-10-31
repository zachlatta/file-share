package files

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUploadLinkIsSingleUseAndCarriesSettings(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{
		Name: "report.pdf", Password: "pw-1", AllowedEmails: []string{"Zach@HackClub.com"},
		Client: "claude", ExpiresAt: h.clock.t.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The namespace is chosen up front, so the final URL is known before upload.
	if link.Namespace == "" || link.URL != "https://files.example.com/"+link.Namespace+"/report.pdf" {
		t.Fatalf("link = %+v", link)
	}
	f, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Name: "ignored.bin", Body: strings.NewReader("%PDF-1.7"), Size: -1})
	if err != nil {
		t.Fatal(err)
	}
	if f.URL != link.URL || !f.HasPassword || !h.svc.CheckPassword(f, "pw-1") || len(f.AllowedEmails) != 1 || f.AllowedEmails[0] != "zach@hackclub.com" {
		t.Fatalf("file = %+v", f)
	}
	if v, _ := h.svc.Versions(ctx, f.ID); v[0].CreatedBy != "claude" {
		t.Fatalf("created_by = %q", v[0].CreatedBy)
	}
	if _, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("again"), Size: -1}); !errors.Is(err, ErrLinkUsed) {
		t.Fatalf("second use: %v", err)
	}
	if _, err := h.svc.UploadLink(ctx, link.ID); !errors.Is(err, ErrLinkUsed) {
		t.Fatalf("lookup after use: %v", err)
	}
}

func TestUploadLinkWithoutNameTakesUploaderName(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{ExpiresAt: h.clock.t.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if link.URL != "" {
		t.Fatalf("url is unknown until the name is: %q", link.URL)
	}
	// A failed attempt (no name) releases the link so it can be retried.
	if _, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("x"), Size: -1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nameless upload: %v", err)
	}
	f, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Name: "photo.jpg", Body: strings.NewReader("x"), Size: -1})
	if err != nil {
		t.Fatal(err)
	}
	if f.Namespace != link.Namespace || f.Name != "photo.jpg" || f.HasPassword {
		t.Fatalf("file = %+v", f)
	}
}

func TestUploadLinkReplacesFile(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "a.txt", "v1")
	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{FileID: f.ID, ExpiresAt: h.clock.t.Add(time.Hour)})
	if err != nil || link.URL != f.URL {
		t.Fatalf("link = %+v %v", link, err)
	}
	g, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("v2"), Size: -1})
	if err != nil || g.ID != f.ID || g.Version != 2 {
		t.Fatalf("replace = %+v %v", g, err)
	}
	if _, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{FileID: f.ID, Password: "x", ExpiresAt: h.clock.t.Add(time.Hour)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replace link with settings: %v", err)
	}
}

func TestUploadLinkValidationAndExpiry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	exp := h.clock.t.Add(time.Hour)
	existing := h.upload(t, "", "taken.txt", "x")
	for name, in := range map[string]UploadLinkInput{
		"bad name":      {Name: "../x", ExpiresAt: exp},
		"bad namespace": {Namespace: "nope", ExpiresAt: exp},
		"bad email":     {AllowedEmails: []string{"not an email"}, ExpiresAt: exp},
	} {
		if _, err := h.svc.CreateUploadLink(ctx, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{Namespace: existing.Namespace, Name: "taken.txt", ExpiresAt: exp}); !errors.Is(err, ErrExists) {
		t.Errorf("taken name: %v", err)
	}
	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{Name: "late.txt", ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	h.clock.t = h.clock.t.Add(2 * time.Hour)
	if _, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("x"), Size: -1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired link: %v", err)
	}
	res, err := h.svc.Purge(ctx)
	if err != nil || res.Links != 1 {
		t.Fatalf("purge expired links: %+v %v", res, err)
	}
	if _, err := h.svc.UploadLink(ctx, "not-a-uuid"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
}

func TestReplaceLinkWithExpectedVersion(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.upload(t, "", "db.duckdb", "v1")
	expires := h.clock.t.Add(time.Hour)
	if _, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{FileID: f.ID, ExpectedVersion: 2, ExpiresAt: expires}); !errors.Is(err, ErrConflict) {
		t.Fatalf("link for a version the file is not at: %v", err)
	}
	if _, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{ExpectedVersion: 1, ExpiresAt: expires}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected version on a new-file link: %v", err)
	}
	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{FileID: f.ID, ExpectedVersion: 1, ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	// Another writer gets in first.
	if _, err := h.svc.Replace(ctx, f.ID, ReplaceInput{Body: strings.NewReader("v2"), Size: -1}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("stale"), Size: -1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale link upload: %v", err)
	}
	if got := h.read(t, f, 0); got != "v2" {
		t.Fatalf("current = %q", got)
	}
}

func linkUploadKey(linkID string) string {
	sum := sha256.Sum256([]byte(linkID))
	return hex.EncodeToString(sum[:16])
}

type blockingReader struct {
	started chan struct{}
	gate    <-chan struct{}
	r       io.Reader
	err     error
	once    sync.Once
}

func (b *blockingReader) Read(p []byte) (int, error) {
	b.once.Do(func() {
		if b.started != nil {
			close(b.started)
		}
	})
	<-b.gate
	if b.err != nil {
		return 0, b.err
	}
	return b.r.Read(p)
}

func TestChunkedLinkCompletionSpansRequestWindowsAndSurvivesCancel(t *testing.T) {
	h := newHarness(t)
	h.svc.completeWait = 20 * time.Millisecond
	ctx := context.Background()

	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{Name: "archive.bin", ExpiresAt: h.clock.t.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	key := linkUploadKey(link.ID)
	for i, part := range []string{"part-one-", "part-two"} {
		if _, err := h.svc.PutPart(ctx, key, i+1, strings.NewReader(part), -1); err != nil {
			t.Fatal(err)
		}
	}

	gate := make(chan struct{})
	started := make(chan struct{})
	complete := func(callCtx context.Context) (File, error) {
		return h.svc.CompleteParts(callCtx, key, 2, func(bgCtx context.Context, r io.Reader) (File, error) {
			return h.svc.UploadWithLink(bgCtx, link.ID, LinkUpload{
				Body: &blockingReader{started: started, gate: gate, r: r}, Size: -1,
			})
		})
	}

	// First request window elapses without client cancellation -> ErrAssembling.
	if _, err := complete(ctx); !errors.Is(err, ErrAssembling) {
		t.Fatalf("first poll = %v, want ErrAssembling", err)
	}
	<-started

	// While in flight, UploadLinkForComplete allows the next poll through.
	if _, done, err := h.svc.UploadLinkForComplete(ctx, link.ID, key); err != nil || done != nil {
		t.Fatalf("UploadLinkForComplete in flight = %+v %v", done, err)
	}

	// A poll whose caller cancels its context does not abort the background join.
	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	if _, err := complete(cancelCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled poll = %v, want context.Canceled", err)
	}

	// Release the join; the next poll receives the assembled file and cleans up parts.
	close(gate)
	f, err := complete(ctx)
	if err != nil {
		t.Fatalf("poll after release: %v", err)
	}
	if got := h.read(t, f, 0); got != "part-one-part-two" {
		t.Fatalf("content = %q", got)
	}
	if len(h.blobs.Keys()) != 1 {
		t.Fatalf("parts not deleted: %v", h.blobs.Keys())
	}

	// Retrying after parts are deleted still returns the file, both from the
	// in-memory completion cache and from upload_links.result_file_id after TTL.
	if f2, err := complete(ctx); err != nil || f2.ID != f.ID {
		t.Fatalf("cached retry = %+v %v", f2, err)
	}
	h.clock.t = h.clock.t.Add(10 * time.Minute)
	if _, done, err := h.svc.UploadLinkForComplete(ctx, link.ID, key); err != nil || done == nil || done.ID != f.ID {
		t.Fatalf("UploadLinkForComplete after cache TTL = %+v %v", done, err)
	}
}

func TestChunkedLinkCompletionStaleClaimAndRestartRecovery(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{Name: "recover.txt", ExpiresAt: h.clock.t.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	key := linkUploadKey(link.ID)
	for i, part := range []string{"hello-", "world"} {
		if _, err := h.svc.PutPart(ctx, key, i+1, strings.NewReader(part), -1); err != nil {
			t.Fatal(err)
		}
	}

	// Simulate another instance (rolling deploy) or prior process claiming the link.
	if _, err := h.svc.db.Exec(ctx, `UPDATE upload_links SET used_at = $2 WHERE id = $1`, link.ID, h.svc.nowUTC()); err != nil {
		t.Fatal(err)
	}

	// While the claim is still fresh (< completeTimeout), another instance must
	// not re-claim it or start a duplicate join.
	h.clock.t = h.clock.t.Add(10 * time.Minute)
	if _, _, err := h.svc.UploadLinkForComplete(ctx, link.ID, key); !errors.Is(err, ErrLinkUsed) {
		t.Fatalf("fresh claim on another instance: %v, want ErrLinkUsed", err)
	}
	if _, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("dup"), Size: -1}); !errors.Is(err, ErrLinkUsed) {
		t.Fatalf("UploadWithLink on fresh claim: %v, want ErrLinkUsed", err)
	}

	// Once the claim is stale (> completeTimeout) and the link has not expired,
	// it can be re-claimed and completed from the existing parts.
	h.clock.t = h.clock.t.Add(25 * time.Minute)
	if _, done, err := h.svc.UploadLinkForComplete(ctx, link.ID, key); err != nil || done != nil {
		t.Fatalf("stale claim UploadLinkForComplete: %+v %v", done, err)
	}
	f, err := h.svc.CompleteParts(ctx, key, 2, func(bgCtx context.Context, r io.Reader) (File, error) {
		return h.svc.UploadWithLink(bgCtx, link.ID, LinkUpload{Body: r, Size: -1})
	})
	if err != nil {
		t.Fatalf("complete stale claim: %v", err)
	}
	if got := h.read(t, f, 0); got != "hello-world" {
		t.Fatalf("content = %q", got)
	}
}

func TestFailedJoinDoesNotReopenCompletedLink(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	link, err := h.svc.CreateUploadLink(ctx, UploadLinkInput{Name: "once.txt", ExpiresAt: h.clock.t.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	started1, gate1 := make(chan struct{}), make(chan struct{})
	done1 := make(chan error, 1)
	go func() {
		_, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{
			Body: &blockingReader{started: started1, gate: gate1, r: strings.NewReader("winner")}, Size: -1,
		})
		done1 <- err
	}()
	<-started1

	// Advance clock past completeTimeout so a second join can re-claim while the first is still finishing.
	h.clock.t = h.clock.t.Add(h.svc.completeTimeout + time.Minute)
	started2, gate2 := make(chan struct{}), make(chan struct{})
	done2 := make(chan error, 1)
	go func() {
		_, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{
			Body: &blockingReader{started: started2, gate: gate2, err: errors.New("late failure")}, Size: -1,
		})
		done2 <- err
	}()
	<-started2

	// Join 1 finishes first and sets result_file_id.
	close(gate1)
	if err := <-done1; err != nil {
		t.Fatalf("join 1: %v", err)
	}

	// Join 2 now fails; its error cleanup must not clear used_at now that result_file_id is set.
	close(gate2)
	if err := <-done2; err == nil {
		t.Fatal("join 2 succeeded unexpectedly")
	}

	if _, err := h.svc.UploadLink(ctx, link.ID); !errors.Is(err, ErrLinkUsed) {
		t.Fatalf("UploadLink after late failure = %v, want ErrLinkUsed", err)
	}
	if _, err := h.svc.UploadWithLink(ctx, link.ID, LinkUpload{Body: strings.NewReader("third"), Size: -1}); !errors.Is(err, ErrLinkUsed) {
		t.Fatalf("UploadWithLink after late failure = %v, want ErrLinkUsed", err)
	}
}

func TestChunkedCompletionCachesBackgroundErrorAndDeduplicatesConcurrentPolls(t *testing.T) {
	h := newHarness(t)
	h.svc.completeWait = 20 * time.Millisecond
	ctx := context.Background()

	const key = "11111111111111111111111111111111"
	if _, err := h.svc.PutPart(ctx, key, 1, strings.NewReader("data"), -1); err != nil {
		t.Fatal(err)
	}

	gate := make(chan struct{})
	var calls atomic.Int32
	complete := func() (File, error) {
		return h.svc.CompleteParts(ctx, key, 1, func(context.Context, io.Reader) (File, error) {
			calls.Add(1)
			<-gate
			return File{}, ErrConflict
		})
	}

	// Poll 1 times out with ErrAssembling while the job is running.
	if _, err := complete(); !errors.Is(err, ErrAssembling) {
		t.Fatalf("poll 1 = %v, want ErrAssembling", err)
	}

	// Job fails during the gap between polls (while no caller is waiting).
	close(gate)
	time.Sleep(15 * time.Millisecond)

	// Poll 2 gets the cached ErrConflict without starting a second join.
	if _, err := complete(); !errors.Is(err, ErrConflict) {
		t.Fatalf("poll 2 = %v, want ErrConflict", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("fn called %d times, want 1", got)
	}

	// Concurrent callers arriving together under a fresh key start only one join.
	const key2 = "22222222222222222222222222222222"
	if _, err := h.svc.PutPart(ctx, key2, 1, strings.NewReader("joined-once"), -1); err != nil {
		t.Fatal(err)
	}
	h.svc.completeWait = time.Second
	var calls2 atomic.Int32
	var wg sync.WaitGroup
	errs := make([]error, 5)
	files := make([]File, 5)
	for i := range 5 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			files[idx], errs[idx] = h.svc.CompleteParts(ctx, key2, 1, func(bgCtx context.Context, r io.Reader) (File, error) {
				calls2.Add(1)
				time.Sleep(20 * time.Millisecond)
				return h.svc.Upload(bgCtx, UploadInput{Name: "once.bin", Body: r, Size: -1})
			})
		}(i)
	}
	wg.Wait()
	if got := calls2.Load(); got != 1 {
		t.Fatalf("concurrent CompleteParts called fn %d times, want 1", got)
	}
	for i := range 5 {
		if errs[i] != nil || files[i].ID != files[0].ID {
			t.Fatalf("caller %d: %+v %v", i, files[i], errs[i])
		}
	}
}
