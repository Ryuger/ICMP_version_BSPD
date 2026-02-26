package store

import (
	"errors"
	"log"
	"sync"
	"time"
)

type MemoryStore struct {
	mu          sync.Mutex
	users       map[string]User
	adminUsers  map[string]AdminUser
	attempts    []loginAttempt
	bans        map[string]ipBan
	clients     map[int64]Client
	clientCerts map[int64]ClientCert
	tokens      map[int64]EnrollToken
	whitelist   map[int64]WhitelistEntry
	audit       []AuditEntry
	userAudit   []UserAuditEntry
	nextID      int64
}

type loginAttempt struct {
	ip       string
	username string
	success  bool
	at       time.Time
}

type ipBan struct {
	until  time.Time
	reason string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:       map[string]User{},
		adminUsers:  map[string]AdminUser{},
		bans:        map[string]ipBan{},
		clients:     map[int64]Client{},
		clientCerts: map[int64]ClientCert{},
		tokens:      map[int64]EnrollToken{},
		whitelist:   map[int64]WhitelistEntry{},
	}
}

func (m *MemoryStore) AddUser(username, passwordHash string, active bool, changedAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[username] = User{ID: m.next(), Username: username, PasswordHash: passwordHash, IsActive: active, PasswordChangedAt: changedAt}
}

func (m *MemoryStore) AddAdminUser(username, passwordHash, role string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.adminUsers[username] = AdminUser{ID: m.next(), Username: username, PasswordHash: passwordHash, Role: role, LastLoginAt: now}
}

func (m *MemoryStore) IsBanned(ip string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneBans(now)
	ban, ok := m.bans[ip]
	if !ok {
		return false, nil
	}
	return ban.until.After(now), nil
}

func (m *MemoryStore) IsWhitelisted(ip string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range m.whitelist {
		if entry.Value == ip {
			return true, nil
		}
	}
	return false, nil
}

func (m *MemoryStore) ListWhitelist() ([]WhitelistEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []WhitelistEntry
	for _, entry := range m.whitelist {
		out = append(out, entry)
	}
	return out, nil
}

func (m *MemoryStore) AddWhitelist(entry WhitelistEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry.ID = m.next()
	m.whitelist[entry.ID] = entry
	return nil
}

func (m *MemoryStore) DeleteWhitelist(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.whitelist, id)
	return nil
}

func (m *MemoryStore) GetUser(username string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	user, ok := m.users[username]
	if !ok {
		return nil, errors.New("not found")
	}
	return &user, nil
}

func (m *MemoryStore) CreateUser(clientID int64, username, passwordHash string, now time.Time) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.users[username]; exists {
		return nil, errors.New("already exists")
	}
	user := User{ID: m.next(), ClientID: clientID, Username: username, PasswordHash: passwordHash, IsActive: true, PasswordChangedAt: now}
	m.users[username] = user
	return &user, nil
}

func (m *MemoryStore) ListUsersByClient(clientID int64) ([]User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []User
	for _, user := range m.users {
		if user.ClientID == clientID {
			out = append(out, user)
		}
	}
	return out, nil
}

func (m *MemoryStore) InsertAttempt(ip, username string, success bool, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts = append(m.attempts, loginAttempt{ip: ip, username: username, success: success, at: now})
	return nil
}

func (m *MemoryStore) CheckConsecutiveFailures(ip string, window time.Duration, limit int, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneAttempts(now.Add(-window))
	count := 0
	cutoff := now.Add(-window)
	for i := len(m.attempts) - 1; i >= 0 && count < limit; i-- {
		attempt := m.attempts[i]
		if attempt.ip != ip || attempt.at.Before(cutoff) {
			continue
		}
		if attempt.success {
			return false, nil
		}
		count++
	}
	return count >= limit, nil
}

func (m *MemoryStore) UpsertBan(ip string, ttl time.Duration, reason string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bans[ip] = ipBan{until: now.Add(ttl), reason: reason}
	return nil
}

func (m *MemoryStore) InsertAudit(eventType, actor, ip, details string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := UserAuditEntry{
		ID:        m.next(),
		EventType: eventType,
		Actor:     actor,
		IP:        ip,
		Details:   details,
		CreatedAt: now,
	}
	m.userAudit = append(m.userAudit, entry)
	log.Printf("user audit event=%s actor=%s ip=%s details=%s", eventType, actor, ip, details)
	return nil
}

func (m *MemoryStore) UpdatePassword(username, passwordHash string, changedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	user, ok := m.users[username]
	if !ok {
		return errors.New("not found")
	}
	user.PasswordHash = passwordHash
	user.PasswordChangedAt = changedAt
	m.users[username] = user
	return nil
}

func (m *MemoryStore) GetAdminUser(username string) (*AdminUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	admin, ok := m.adminUsers[username]
	if !ok {
		return nil, errors.New("not found")
	}
	return &admin, nil
}

func (m *MemoryStore) UpdateAdminLogin(username string, lastLogin time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	admin, ok := m.adminUsers[username]
	if !ok {
		return errors.New("not found")
	}
	admin.LastLoginAt = lastLogin
	m.adminUsers[username] = admin
	return nil
}

func (m *MemoryStore) CreateClient(name string, now time.Time) (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	client := Client{ID: m.next(), Name: name, Status: "active", CreatedAt: now, UpdatedAt: now}
	m.clients[client.ID] = client
	return &client, nil
}

func (m *MemoryStore) ListClients() ([]Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	clients := make([]Client, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	return clients, nil
}

func (m *MemoryStore) GetClient(id int64) (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	client, ok := m.clients[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return &client, nil
}

func (m *MemoryStore) SetClientStatus(id int64, status string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	client, ok := m.clients[id]
	if !ok {
		return errors.New("not found")
	}
	client.Status = status
	client.UpdatedAt = now
	m.clients[id] = client
	return nil
}

func (m *MemoryStore) InsertClientCert(cert ClientCert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert.ID = m.next()
	m.clientCerts[cert.ID] = cert
	return nil
}

func (m *MemoryStore) ListClientCerts(clientID int64) ([]ClientCert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ClientCert
	for _, cert := range m.clientCerts {
		if clientID == 0 || cert.ClientID == clientID {
			out = append(out, cert)
		}
	}
	return out, nil
}

func (m *MemoryStore) FindClientCertByFingerprint(fingerprint string) (*ClientCert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cert := range m.clientCerts {
		if cert.FingerprintSHA256 == fingerprint {
			return &cert, nil
		}
	}
	return nil, errors.New("not found")
}

func (m *MemoryStore) RevokeClientCert(certID int64, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert, ok := m.clientCerts[certID]
	if !ok {
		return errors.New("not found")
	}
	cert.Status = "revoked"
	cert.RevokedAt = now
	m.clientCerts[certID] = cert
	return nil
}

func (m *MemoryStore) CreateEnrollToken(token EnrollToken) (*EnrollToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token.ID = m.next()
	m.tokens[token.ID] = token
	return &token, nil
}

func (m *MemoryStore) ListEnrollTokens() ([]EnrollToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []EnrollToken
	for _, token := range m.tokens {
		out = append(out, token)
	}
	return out, nil
}

func (m *MemoryStore) RevokeEnrollToken(id int64, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	token, ok := m.tokens[id]
	if !ok {
		return errors.New("not found")
	}
	if token.UsedAt.After(time.Time{}) {
		return nil
	}
	token.RevokedAt = now
	m.tokens[id] = token
	return nil
}

func (m *MemoryStore) ConsumeEnrollToken(tokenHash string, now time.Time) (*EnrollToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, token := range m.tokens {
		if token.TokenHash != tokenHash {
			continue
		}
		if token.UsedAt.After(time.Time{}) || token.RevokedAt.After(time.Time{}) || token.ExpiresAt.Before(now) {
			return nil, errors.New("token invalid")
		}
		token.UsedAt = now
		m.tokens[id] = token
		return &token, nil
	}
	return nil, errors.New("token not found")
}

func (m *MemoryStore) InsertAuditEntry(entry AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry.ID = m.next()
	m.audit = append(m.audit, entry)
	return nil
}

func (m *MemoryStore) ListAudit(limit int) ([]AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > len(m.audit) {
		limit = len(m.audit)
	}
	start := len(m.audit) - limit
	if start < 0 {
		start = 0
	}
	out := make([]AuditEntry, 0, limit)
	for i := len(m.audit) - 1; i >= start; i-- {
		out = append(out, m.audit[i])
	}
	return out, nil
}

func (m *MemoryStore) ListUserAudit(limit int) ([]UserAuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > len(m.userAudit) {
		limit = len(m.userAudit)
	}
	start := len(m.userAudit) - limit
	if start < 0 {
		start = 0
	}
	out := make([]UserAuditEntry, 0, limit)
	for i := len(m.userAudit) - 1; i >= start; i-- {
		out = append(out, m.userAudit[i])
	}
	return out, nil
}

func (m *MemoryStore) pruneBans(now time.Time) {
	for ip, ban := range m.bans {
		if !ban.until.After(now) {
			delete(m.bans, ip)
		}
	}
}

func (m *MemoryStore) pruneAttempts(cutoff time.Time) {
	if len(m.attempts) == 0 {
		return
	}

	idx := 0
	for _, attempt := range m.attempts {
		if attempt.at.After(cutoff) {
			m.attempts[idx] = attempt
			idx++
		}
	}
	m.attempts = m.attempts[:idx]
}

func (m *MemoryStore) next() int64 {
	m.nextID++
	return m.nextID
}
