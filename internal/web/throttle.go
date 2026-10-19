package web

import (
	"sync"
	"time"
)

// Password guessing limits, per file. Each wrong password is slowed down,
// and once a file has had maxPasswordFailures wrong guesses within the
// window, every password attempt on it is refused until the window ends.
// Visitors who already unlocked it (cookie or email) are not affected.
var (
	wrongPasswordDelay  = 250 * time.Millisecond
	maxPasswordFailures = 20
	passwordWindow      = 15 * time.Minute
)

// failureLimiter counts failures per key in a fixed window. It is in
// memory, so a restart resets it; bcrypt keeps each guess slow regardless.
type failureLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	now    func() time.Time
	keys   map[string]failureWindow
}

type failureWindow struct {
	start time.Time
	count int
}

func newFailureLimiter(max int, window time.Duration) *failureLimiter {
	return &failureLimiter{max: max, window: window, now: time.Now, keys: map[string]failureWindow{}}
}

// allowed reports whether key may make another attempt.
func (l *failureLimiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.keys[key]
	if !ok {
		return true
	}
	if l.now().Sub(w.start) > l.window {
		delete(l.keys, key)
		return true
	}
	return w.count < l.max
}

func (l *failureLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, w := range l.keys {
		if now.Sub(w.start) > l.window {
			delete(l.keys, k)
		}
	}
	w := l.keys[key]
	if w.count == 0 {
		w.start = now
	}
	w.count++
	l.keys[key] = w
}
