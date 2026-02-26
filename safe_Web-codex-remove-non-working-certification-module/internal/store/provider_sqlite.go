//go:build sqlite

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const defaultSQLitePath = "data/safe_web.db"

type SQLiteStore struct {
	db *sql.DB
}

func (s *SQLiteStore) AddAdminUser(username, passwordHash, role string, now time.Time) {
	_, _ = s.db.Exec(
		`INSERT INTO admin_users (username, password_hash, role, created_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, role = excluded.role`,
		username, passwordHash, role, now,
	)
}

func NewStore() (Store, error) {
	path := strings.TrimSpace(os.Getenv("SQLITE_PATH"))
	if path == "" {
		path = defaultSQLitePath
	}

	dsn := path
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		dsn = "file:" + filepath.ToSlash(path)
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		return nil, err
	}

	store := &SQLiteStore{db: db}
	if err := store.ensureSchema(); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *SQLiteStore) ensureSchema() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_id INTEGER,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT 1,
			password_changed_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL,
			FOREIGN KEY(client_id) REFERENCES clients(id)
		);`,
		`CREATE TABLE IF NOT EXISTS admin_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'admin',
			last_login_at DATETIME,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			value TEXT NOT NULL,
			owner_type TEXT NOT NULL,
			owner_id INTEGER NOT NULL DEFAULT 0,
			label TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS login_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			username TEXT,
			success BOOLEAN NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS ip_bans (
			ip TEXT PRIMARY KEY,
			banned_until DATETIME NOT NULL,
			reason TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL,
			actor TEXT,
			ip TEXT,
			details TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS admin_audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			target_type TEXT NOT NULL,
			target_id TEXT NOT NULL,
			metadata_json TEXT,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS client_certs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_id INTEGER NOT NULL,
			serial TEXT NOT NULL,
			fingerprint_sha256 TEXT NOT NULL,
			not_before DATETIME NOT NULL,
			not_after DATETIME NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME NOT NULL,
			revoked_at DATETIME,
			FOREIGN KEY(client_id) REFERENCES clients(id)
		);`,
		`CREATE TABLE IF NOT EXISTS enroll_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token_hash TEXT NOT NULL,
			client_id INTEGER NOT NULL,
			expires_at DATETIME NOT NULL,
			used_at DATETIME,
			revoked_at DATETIME,
			created_at DATETIME NOT NULL,
			FOREIGN KEY(client_id) REFERENCES clients(id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_users_client ON users(client_id);`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time ON login_attempts(username, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_ip_bans_until ON ip_bans(banned_until);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_admin_audit_log_time ON admin_audit_log(created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_client_certs_fingerprint ON client_certs(fingerprint_sha256);`,
		`CREATE INDEX IF NOT EXISTS idx_enroll_tokens_hash ON enroll_tokens(token_hash);`,
		`CREATE INDEX IF NOT EXISTS idx_whitelist_value ON whitelist(value);`,
	}

	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("sqlite schema: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) IsBanned(ip string, now time.Time) (bool, error) {
	var bannedUntil time.Time
	err := s.db.QueryRow(
		`SELECT banned_until FROM ip_bans WHERE ip = ? AND banned_until > ?`,
		ip, now,
	).Scan(&bannedUntil)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *SQLiteStore) IsWhitelisted(ip string) (bool, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM whitelist WHERE value = ?`, ip).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *SQLiteStore) ListWhitelist() ([]WhitelistEntry, error) {
	rows, err := s.db.Query(`SELECT id, value, owner_type, owner_id, label, created_at FROM whitelist ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []WhitelistEntry
	for rows.Next() {
		var entry WhitelistEntry
		if err := rows.Scan(&entry.ID, &entry.Value, &entry.OwnerType, &entry.OwnerID, &entry.Label, &entry.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *SQLiteStore) AddWhitelist(entry WhitelistEntry) error {
	_, err := s.db.Exec(
		`INSERT INTO whitelist (value, owner_type, owner_id, label, created_at) VALUES (?, ?, ?, ?, ?)`,
		entry.Value, entry.OwnerType, entry.OwnerID, entry.Label, entry.CreatedAt,
	)
	return err
}

func (s *SQLiteStore) DeleteWhitelist(id int64) error {
	_, err := s.db.Exec(`DELETE FROM whitelist WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) GetUser(username string) (*User, error) {
	var user User
	err := s.db.QueryRow(
		`SELECT id, client_id, username, password_hash, is_active, password_changed_at FROM users WHERE username = ?`,
		username,
	).Scan(&user.ID, &user.ClientID, &user.Username, &user.PasswordHash, &user.IsActive, &user.PasswordChangedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *SQLiteStore) CreateUser(clientID int64, username, passwordHash string, now time.Time) (*User, error) {
	_, err := s.db.Exec(
		`INSERT INTO users (client_id, username, password_hash, is_active, password_changed_at, created_at)
		 VALUES (?, ?, ?, 1, ?, ?)`,
		clientID, username, passwordHash, now, now,
	)
	if err != nil {
		return nil, err
	}
	return s.GetUser(username)
}

func (s *SQLiteStore) ListUsersByClient(clientID int64) ([]User, error) {
	rows, err := s.db.Query(
		`SELECT id, client_id, username, password_hash, is_active, password_changed_at FROM users WHERE client_id = ?`,
		clientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.ClientID, &user.Username, &user.PasswordHash, &user.IsActive, &user.PasswordChangedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func (s *SQLiteStore) InsertAttempt(ip, username string, success bool, now time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO login_attempts (ip, username, success, created_at) VALUES (?, ?, ?, ?)`,
		ip, username, success, now,
	)
	return err
}

func (s *SQLiteStore) CheckConsecutiveFailures(ip string, window time.Duration, limit int, now time.Time) (bool, error) {
	rows, err := s.db.Query(
		`SELECT success
		 FROM login_attempts
		 WHERE ip = ? AND created_at >= ?
		 ORDER BY created_at DESC
		 LIMIT ?`,
		ip, now.Add(-window), limit,
	)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var success bool
		if err := rows.Scan(&success); err != nil {
			return false, err
		}
		if success {
			return false, nil
		}
		count++
	}
	return count >= limit, nil
}

func (s *SQLiteStore) UpsertBan(ip string, ttl time.Duration, reason string, now time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO ip_bans (ip, banned_until, reason, created_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET banned_until = excluded.banned_until, reason = excluded.reason`,
		ip, now.Add(ttl), reason, now,
	)
	return err
}

func (s *SQLiteStore) InsertAudit(eventType, actor, ip, details string, now time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_log (event_type, actor, ip, details, created_at) VALUES (?, ?, ?, ?, ?)`,
		eventType, actor, ip, details, now,
	)
	return err
}

func (s *SQLiteStore) UpdatePassword(username, passwordHash string, changedAt time.Time) error {
	_, err := s.db.Exec(
		`UPDATE users SET password_hash = ?, password_changed_at = ? WHERE username = ?`,
		passwordHash, changedAt, username,
	)
	return err
}

func (s *SQLiteStore) GetAdminUser(username string) (*AdminUser, error) {
	var admin AdminUser
	var lastLogin sql.NullTime
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, role, last_login_at FROM admin_users WHERE username = ?`,
		username,
	).Scan(&admin.ID, &admin.Username, &admin.PasswordHash, &admin.Role, &lastLogin)
	if err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		admin.LastLoginAt = lastLogin.Time
	}
	return &admin, nil
}

func (s *SQLiteStore) UpdateAdminLogin(username string, lastLogin time.Time) error {
	_, err := s.db.Exec(
		`UPDATE admin_users SET last_login_at = ? WHERE username = ?`,
		lastLogin, username,
	)
	return err
}

func (s *SQLiteStore) CreateClient(name string, now time.Time) (*Client, error) {
	_, err := s.db.Exec(
		`INSERT INTO clients (name, status, created_at, updated_at) VALUES (?, 'active', ?, ?)`,
		name, now, now,
	)
	if err != nil {
		return nil, err
	}
	rowID, err := s.lastInsertID()
	if err != nil {
		return nil, err
	}
	return s.GetClient(rowID)
}

func (s *SQLiteStore) ListClients() ([]Client, error) {
	rows, err := s.db.Query(`SELECT id, name, status, created_at, updated_at FROM clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var client Client
		if err := rows.Scan(&client.ID, &client.Name, &client.Status, &client.CreatedAt, &client.UpdatedAt); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, nil
}

func (s *SQLiteStore) GetClient(id int64) (*Client, error) {
	var client Client
	err := s.db.QueryRow(
		`SELECT id, name, status, created_at, updated_at FROM clients WHERE id = ?`,
		id,
	).Scan(&client.ID, &client.Name, &client.Status, &client.CreatedAt, &client.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (s *SQLiteStore) SetClientStatus(id int64, status string, now time.Time) error {
	_, err := s.db.Exec(
		`UPDATE clients SET status = ?, updated_at = ? WHERE id = ?`,
		status, now, id,
	)
	return err
}

func (s *SQLiteStore) InsertClientCert(cert ClientCert) error {
	_, err := s.db.Exec(
		`INSERT INTO client_certs (client_id, serial, fingerprint_sha256, not_before, not_after, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		cert.ClientID, cert.Serial, cert.FingerprintSHA256, cert.NotBefore, cert.NotAfter, cert.Status, cert.CreatedAt,
	)
	return err
}

func (s *SQLiteStore) ListClientCerts(clientID int64) ([]ClientCert, error) {
	query := `SELECT id, client_id, serial, fingerprint_sha256, not_before, not_after, status, created_at, revoked_at FROM client_certs`
	args := []any{}
	if clientID != 0 {
		query += ` WHERE client_id = ?`
		args = append(args, clientID)
	}
	query += ` ORDER BY id DESC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []ClientCert
	for rows.Next() {
		var cert ClientCert
		var revoked sql.NullTime
		if err := rows.Scan(&cert.ID, &cert.ClientID, &cert.Serial, &cert.FingerprintSHA256, &cert.NotBefore, &cert.NotAfter, &cert.Status, &cert.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		if revoked.Valid {
			cert.RevokedAt = revoked.Time
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (s *SQLiteStore) FindClientCertByFingerprint(fingerprint string) (*ClientCert, error) {
	var cert ClientCert
	var revoked sql.NullTime
	err := s.db.QueryRow(
		`SELECT id, client_id, serial, fingerprint_sha256, not_before, not_after, status, created_at, revoked_at
		 FROM client_certs WHERE fingerprint_sha256 = ?`,
		fingerprint,
	).Scan(&cert.ID, &cert.ClientID, &cert.Serial, &cert.FingerprintSHA256, &cert.NotBefore, &cert.NotAfter, &cert.Status, &cert.CreatedAt, &revoked)
	if err != nil {
		return nil, err
	}
	if revoked.Valid {
		cert.RevokedAt = revoked.Time
	}
	return &cert, nil
}

func (s *SQLiteStore) RevokeClientCert(certID int64, now time.Time) error {
	_, err := s.db.Exec(
		`UPDATE client_certs SET status = 'revoked', revoked_at = ? WHERE id = ?`,
		now, certID,
	)
	return err
}

func (s *SQLiteStore) CreateEnrollToken(token EnrollToken) (*EnrollToken, error) {
	_, err := s.db.Exec(
		`INSERT INTO enroll_tokens (token_hash, client_id, expires_at, created_at)
		 VALUES (?, ?, ?, ?)`,
		token.TokenHash, token.ClientID, token.ExpiresAt, token.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	rowID, err := s.lastInsertID()
	if err != nil {
		return nil, err
	}
	return s.getEnrollTokenByID(rowID)
}

func (s *SQLiteStore) ListEnrollTokens() ([]EnrollToken, error) {
	rows, err := s.db.Query(
		`SELECT id, token_hash, client_id, expires_at, used_at, revoked_at, created_at
		 FROM enroll_tokens ORDER BY id DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []EnrollToken
	for rows.Next() {
		var token EnrollToken
		var used sql.NullTime
		var revoked sql.NullTime
		if err := rows.Scan(&token.ID, &token.TokenHash, &token.ClientID, &token.ExpiresAt, &used, &revoked, &token.CreatedAt); err != nil {
			return nil, err
		}
		if used.Valid {
			token.UsedAt = used.Time
		}
		if revoked.Valid {
			token.RevokedAt = revoked.Time
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (s *SQLiteStore) RevokeEnrollToken(id int64, now time.Time) error {
	_, err := s.db.Exec(
		`UPDATE enroll_tokens SET revoked_at = ? WHERE id = ? AND used_at IS NULL`,
		now, id,
	)
	return err
}

func (s *SQLiteStore) ConsumeEnrollToken(tokenHash string, now time.Time) (*EnrollToken, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var token EnrollToken
	var used sql.NullTime
	var revoked sql.NullTime
	err = tx.QueryRow(
		`SELECT id, token_hash, client_id, expires_at, used_at, revoked_at, created_at
		 FROM enroll_tokens WHERE token_hash = ?`,
		tokenHash,
	).Scan(&token.ID, &token.TokenHash, &token.ClientID, &token.ExpiresAt, &used, &revoked, &token.CreatedAt)
	if err != nil {
		return nil, err
	}
	if used.Valid {
		token.UsedAt = used.Time
	}
	if revoked.Valid {
		token.RevokedAt = revoked.Time
	}

	if used.Valid || revoked.Valid || token.ExpiresAt.Before(now) {
		return nil, errors.New("token invalid")
	}

	result, err := tx.Exec(
		`UPDATE enroll_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`,
		now, token.ID,
	)
	if err != nil {
		return nil, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, errors.New("token invalid")
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	token.UsedAt = now
	return &token, nil
}

func (s *SQLiteStore) InsertAuditEntry(entry AuditEntry) error {
	_, err := s.db.Exec(
		`INSERT INTO admin_audit_log (actor, action, target_type, target_id, metadata_json, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		entry.Actor, entry.Action, entry.TargetType, entry.TargetID, entry.Metadata, entry.CreatedAt,
	)
	return err
}

func (s *SQLiteStore) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, actor, action, target_type, target_id, metadata_json, created_at
		 FROM admin_audit_log ORDER BY id DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.ID, &entry.Actor, &entry.Action, &entry.TargetType, &entry.TargetID, &entry.Metadata, &entry.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *SQLiteStore) ListUserAudit(limit int) ([]UserAuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, event_type, COALESCE(actor, ''), COALESCE(ip, ''), COALESCE(details, '{}'), created_at
		 FROM audit_log ORDER BY id DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []UserAuditEntry
	for rows.Next() {
		var entry UserAuditEntry
		if err := rows.Scan(&entry.ID, &entry.EventType, &entry.Actor, &entry.IP, &entry.Details, &entry.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *SQLiteStore) lastInsertID() (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT last_insert_rowid()`).Scan(&id)
	return id, err
}

func (s *SQLiteStore) getEnrollTokenByID(id int64) (*EnrollToken, error) {
	var token EnrollToken
	var used sql.NullTime
	var revoked sql.NullTime
	err := s.db.QueryRow(
		`SELECT id, token_hash, client_id, expires_at, used_at, revoked_at, created_at
		 FROM enroll_tokens WHERE id = ?`,
		id,
	).Scan(&token.ID, &token.TokenHash, &token.ClientID, &token.ExpiresAt, &used, &revoked, &token.CreatedAt)
	if err != nil {
		return nil, err
	}
	if used.Valid {
		token.UsedAt = used.Time
	}
	if revoked.Valid {
		token.RevokedAt = revoked.Time
	}
	return &token, nil
}
