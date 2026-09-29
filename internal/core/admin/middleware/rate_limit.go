package middleware

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]rateEntry
	lastGC  time.Time
}

type rateEntry struct {
	count int
	start time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{limit: limit, window: window, entries: make(map[string]rateEntry)}
}

func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.lastGC.IsZero() || now.Sub(l.lastGC) >= l.window {
		for entryKey, candidate := range l.entries {
			if now.Sub(candidate.start) >= l.window {
				delete(l.entries, entryKey)
			}
		}
		l.lastGC = now
	}
	entry := l.entries[key]
	if entry.start.IsZero() || now.Sub(entry.start) >= l.window {
		l.entries[key] = rateEntry{count: 1, start: now}
		return true
	}
	if entry.count >= l.limit {
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}
