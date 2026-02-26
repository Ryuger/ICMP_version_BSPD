package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	states map[string]*state
}

type state struct {
	count int
	start time.Time
}

func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:  limit,
		window: window,
		states: map[string]*state{},
	}
}

func (l *Limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.prune(now)

	st, ok := l.states[key]
	if !ok {
		l.states[key] = &state{count: 1, start: now}
		return true
	}

	if now.Sub(st.start) >= l.window {
		st.start = now
		st.count = 1
		return true
	}

	if st.count >= l.limit {
		return false
	}

	st.count++
	return true
}

func (l *Limiter) prune(now time.Time) {
	for key, st := range l.states {
		if now.Sub(st.start) >= l.window {
			delete(l.states, key)
		}
	}
}
