package soloid

import (
	"context"
	"math"
	"sync"
	"time"
)

type loginEntry struct {
	gate     chan struct{}
	refs     int
	failures int
	expires  time.Time
}
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginEntry
	queued  int
}
type loginResult struct {
	user       *User
	outcome    string
	retryAfter int
}

// The gate serializes an email's checks; mu protects bookkeeping, never Argon2.
// Entries include in-flight reservations, so concurrent new emails cannot overfill the table.
func (l *loginLimiter) attempt(ctx context.Context, r *Runtime, clientID, email, password string, now func() time.Time) (loginResult, error) {
	key := NormalizeEmail(email)
	l.mu.Lock()
	for k, e := range l.entries {
		if e.refs == 0 && !now().Before(e.expires) {
			delete(l.entries, k)
		}
	}
	e := l.entries[key]
	if l.queued >= 32 || (e == nil && len(l.entries) >= 10000) {
		l.mu.Unlock()
		return loginResult{}, ErrBusy
	}
	if e == nil {
		e = &loginEntry{gate: make(chan struct{}, 1)}
		l.entries[key] = e
	}
	e.refs++
	l.queued++
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		e.refs--
		l.queued--
		if e.refs == 0 && e.failures == 0 {
			delete(l.entries, key)
		}
		l.mu.Unlock()
	}()
	select {
	case e.gate <- struct{}{}:
	case <-ctx.Done():
		return loginResult{}, ctx.Err()
	}
	defer func() { <-e.gate }()
	l.mu.Lock()
	if !now().Before(e.expires) {
		e.failures = 0
	}
	if e.failures >= 5 {
		retry := int(math.Ceil(e.expires.Sub(now()).Seconds()))
		l.mu.Unlock()
		return loginResult{outcome: "rate_limited", retryAfter: retry}, nil
	}
	l.mu.Unlock()
	u := r.emails[key]
	hash := r.dummyHash
	if u != nil {
		hash = u.PasswordHash
	}
	correct, err := verifyPassword(hash, password)
	if err != nil {
		return loginResult{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if correct && u != nil {
		if client := r.clients[clientID]; client != nil && allowed(client, u) {
			e.failures = 0
			return loginResult{user: u, outcome: "success"}, nil
		}
		return loginResult{outcome: "failed"}, nil
	}
	if e.failures == 0 || !now().Before(e.expires) {
		e.failures = 0
		e.expires = now().Add(time.Hour)
	}
	e.failures++
	if e.failures == 5 {
		e.expires = now().Add(15 * time.Minute)
	}
	return loginResult{outcome: "failed"}, nil
}
