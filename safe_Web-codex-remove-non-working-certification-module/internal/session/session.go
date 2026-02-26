package session

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type Session struct {
	ID         string
	Username   string
	ExpiresAt  time.Time
	MustChange bool
	CSRFToken  string
}

type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ttl      time.Duration
}

func NewStore(ttl time.Duration) *Store {
	return &Store{
		sessions: map[string]*Session{},
		ttl:      ttl,
	}
}

func (s *Store) Create(username string, mustChange bool, now time.Time) (*Session, error) {
	id, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return nil, err
	}

	newSession := &Session{
		ID:         id,
		Username:   username,
		ExpiresAt:  now.Add(s.ttl),
		MustChange: mustChange,
		CSRFToken:  csrf,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = newSession
	return newSession, nil
}

func (s *Store) Get(id string, now time.Time) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)

	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	if now.After(sess.ExpiresAt) {
		delete(s.sessions, id)
		return nil, false
	}
	return sess, true
}

func (s *Store) Update(id string, update func(*Session)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		update(sess)
	}
}

func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *Store) prune(now time.Time) {
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
