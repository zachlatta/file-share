package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFailureLimiterWindow(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	l := newFailureLimiter(2, 15*time.Minute)
	l.now = func() time.Time { return now }
	if !l.allowed("a") {
		t.Fatal("fresh key is limited")
	}
	l.fail("a")
	l.fail("a")
	if l.allowed("a") || !l.allowed("b") {
		t.Fatal("limit is not per key")
	}
	now = now.Add(15*time.Minute + time.Second)
	if !l.allowed("a") {
		t.Fatal("limit outlived its window")
	}
}

// Wrong passwords from scripts (?password= and Basic auth) are slowed down,
// audited and counted like the form, and enough of them lock out further
// guesses at that file. Visitors who already unlocked it keep access.
func TestPasswordGuessingIsLimited(t *testing.T) {
	restore := wrongPasswordDelay
	wrongPasswordDelay = 0
	t.Cleanup(func() { wrongPasswordDelay = restore })
	e := newEnv(t)
	e.limiter.max = 3
	f := e.upload(t, "secret.txt", "classified", "opensesame")
	other := e.upload(t, "other.txt", "other", "opensesame")

	unlocked := e.do(visitor(http.MethodPost, urlPath(f), "password=opensesame")).Result().Cookies()[0]
	if rec := e.do(visitor(http.MethodGet, urlPath(f)+"?password=guess-1", "")); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Wrong password") {
		t.Fatalf("wrong query password: %d", rec.Code)
	}
	req := visitor(http.MethodGet, urlPath(f), "")
	req.SetBasicAuth("", "guess-2")
	e.do(req)
	e.do(visitor(http.MethodPost, urlPath(f), "password=guess-3"))

	got := e.events(t)
	var vias []string
	for _, ev := range got {
		if ev.Event == "wrong_password" {
			vias = append(vias, ev.Via)
		}
	}
	if strings.Join(vias, " ") != "password_form basic_auth password_query" {
		t.Fatalf("wrong_password events = %v", vias)
	}

	for _, req := range []*http.Request{
		visitor(http.MethodGet, urlPath(f)+"?password=opensesame", ""),
		visitor(http.MethodPost, urlPath(f), "password=opensesame"),
	} {
		rec := e.do(req)
		if rec.Code != http.StatusTooManyRequests || strings.Contains(rec.Body.String(), "classified") || !strings.Contains(rec.Body.String(), "Too many") {
			t.Fatalf("%s while locked: %d %s", req.Method, rec.Code, rec.Body)
		}
	}
	req = visitor(http.MethodGet, urlPath(f), "")
	req.AddCookie(unlocked)
	if rec := e.do(req); rec.Code != 200 || rec.Body.String() != "classified" {
		t.Fatalf("unlocked visitor while locked: %d", rec.Code)
	}
	if rec := e.do(httptest.NewRequest(http.MethodGet, urlPath(other)+"?password=opensesame", nil)); rec.Code != 200 {
		t.Fatalf("other file: %d", rec.Code)
	}
}
