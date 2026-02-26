//go:build postgres

package store

import (
	"database/sql"
	"errors"
	"os"
	"time"

	_ "github.com/lib/pq"
)

const defaultMaxConns = 10

type PostgresStore struct {
	db *sql.DB
}

func NewStore() (Store, error) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		return nil, errors.New("DB_DSN is required")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(defaultMaxConns)
	db.SetMaxIdleConns(defaultMaxConns)
	db.SetConnMaxLifetime(30 * time.Minute)

	return &PostgresStore{db: db}, nil
}

func (p *PostgresStore) IsBanned(ip string, now time.Time) (bool, error) {
	var bannedUntil time.Time
	err := p.db.QueryRow(
		`SELECT banned_until FROM ip_bans WHERE ip = $1 AND banned_until > $2`,
		ip, now,
	).Scan(&bannedUntil)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (p *PostgresStore) IsWhitelisted(ip string) (bool, error) {
	var id int64
	err := p.db.QueryRow(`SELECT id FROM whitelist WHERE value = $1`, ip).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (p *PostgresStore) ListWhitelist() ([]WhitelistEntry, error) {
	rows, err := p.db.Query(`SELECT id, value, owner_type, owner_id, label, created_at FROM whitelist ORDER BY id`)
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

func (p *PostgresStore) AddWhitelist(entry WhitelistEntry) error {
	_, err := p.db.Exec(
		`INSERT INTO whitelist (value, owner_type, owner_id, label, created_at) VALUES ($1,$2,$3,$4,$5)`,
		entry.Value, entry.OwnerType, entry.OwnerID, entry.Label, entry.CreatedAt,
	)
	return err
}

func (p *PostgresStore) DeleteWhitelist(id int64) error {
	_, err := p.db.Exec(`DELETE FROM whitelist WHERE id = $1`, id)
	return err
}

func (p *PostgresStore) GetUser(username string) (*User, error) {
	var user User
	err := p.db.QueryRow(
		`SELECT id, client_id, username, password_hash, is_active, password_changed_at FROM users WHERE username = $1`,
		username,
	).Scan(&user.ID, &user.ClientID, &user.Username, &user.PasswordHash, &user.IsActive, &user.PasswordChangedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *PostgresStore) CreateUser(clientID int64, username, passwordHash string, now time.Time) (*User, error) {
	var user User
	err := p.db.QueryRow(
		`INSERT INTO users (client_id, username, password_hash, is_active, password_changed_at, created_at)
		 VALUES ($1,$2,$3,true,$4,$4)
		 RETURNING id, client_id, username, password_hash, is_active, password_changed_at`,
		clientID, username, passwordHash, now,
	).Scan(&user.ID, &user.ClientID, &user.Username, &user.PasswordHash, &user.IsActive, &user.PasswordChangedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *PostgresStore) ListUsersByClient(clientID int64) ([]User, error) {
	rows, err := p.db.Query(
		`SELECT id, client_id, username, password_hash, is_active, password_changed_at FROM users WHERE client_id = $1`,
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

func (p *PostgresStore) InsertAttempt(ip, username string, success bool, now time.Time) error {
	_, err := p.db.Exec(
		`INSERT INTO login_attempts (ip, username, success, created_at) VALUES ($1,$2,$3,$4)`,
		ip, username, success, now,
	)
	return err
}

func (p *PostgresStore) CheckConsecutiveFailures(ip string, window time.Duration, limit int, now time.Time) (bool, error) {
	rows, err := p.db.Query(`
		SELECT success
		FROM login_attempts
		WHERE ip = $1 AND created_at >= $2
		ORDER BY created_at DESC
		LIMIT $3
	`, ip, now.Add(-window), limit)
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

func (p *PostgresStore) UpsertBan(ip string, ttl time.Duration, reason string, now time.Time) error {
	_, err := p.db.Exec(`
		INSERT INTO ip_bans (ip, banned_until, reason, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (ip) DO UPDATE
		SET banned_until = EXCLUDED.banned_until, reason = EXCLUDED.reason
	`, ip, now.Add(ttl), reason, now)
	return err
}

func (p *PostgresStore) InsertAudit(eventType, actor, ip, details string, now time.Time) error {
	_, err := p.db.Exec(
		`INSERT INTO audit_log (event_type, actor, ip, details, created_at) VALUES ($1,$2,$3,$4::jsonb,$5)`,
		eventType, actor, ip, details, now,
	)
	return err
}

func (p *PostgresStore) UpdatePassword(username, passwordHash string, changedAt time.Time) error {
	_, err := p.db.Exec(
		`UPDATE users SET password_hash = $1, password_changed_at = $2 WHERE username = $3`,
		passwordHash, changedAt, username,
	)
	return err
}

func (p *PostgresStore) GetAdminUser(username string) (*AdminUser, error) {
	var admin AdminUser
	var lastLogin sql.NullTime
	err := p.db.QueryRow(
		`SELECT id, username, password_hash, role, last_login_at FROM admin_users WHERE username = $1`,
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

func (p *PostgresStore) UpdateAdminLogin(username string, lastLogin time.Time) error {
	_, err := p.db.Exec(
		`UPDATE admin_users SET last_login_at = $1 WHERE username = $2`,
		lastLogin, username,
	)
	return err
}

func (p *PostgresStore) CreateClient(name string, now time.Time) (*Client, error) {
	var client Client
	err := p.db.QueryRow(
		`INSERT INTO clients (name, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)
		 RETURNING id, name, status, created_at, updated_at`,
		name, now,
	).Scan(&client.ID, &client.Name, &client.Status, &client.CreatedAt, &client.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (p *PostgresStore) ListClients() ([]Client, error) {
	rows, err := p.db.Query(`SELECT id, name, status, created_at, updated_at FROM clients ORDER BY id`)
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

func (p *PostgresStore) GetClient(id int64) (*Client, error) {
	var client Client
	err := p.db.QueryRow(
		`SELECT id, name, status, created_at, updated_at FROM clients WHERE id = $1`,
		id,
	).Scan(&client.ID, &client.Name, &client.Status, &client.CreatedAt, &client.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (p *PostgresStore) SetClientStatus(id int64, status string, now time.Time) error {
	_, err := p.db.Exec(
		`UPDATE clients SET status = $1, updated_at = $2 WHERE id = $3`,
		status, now, id,
	)
	return err
}

func (p *PostgresStore) InsertClientCert(cert ClientCert) error {
	_, err := p.db.Exec(
		`INSERT INTO client_certs (client_id, serial, fingerprint_sha256, not_before, not_after, status, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		cert.ClientID, cert.Serial, cert.FingerprintSHA256, cert.NotBefore, cert.NotAfter, cert.Status, cert.CreatedAt,
	)
	return err
}

func (p *PostgresStore) ListClientCerts(clientID int64) ([]ClientCert, error) {
	query := `SELECT id, client_id, serial, fingerprint_sha256, not_before, not_after, status, created_at, revoked_at
		FROM client_certs`
	args := []any{}
	if clientID != 0 {
		query += " WHERE client_id = $1"
		args = append(args, clientID)
	}
	query += " ORDER BY id DESC"

	rows, err := p.db.Query(query, args...)
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

func (p *PostgresStore) FindClientCertByFingerprint(fingerprint string) (*ClientCert, error) {
	var cert ClientCert
	var revoked sql.NullTime
	err := p.db.QueryRow(
		`SELECT id, client_id, serial, fingerprint_sha256, not_before, not_after, status, created_at, revoked_at
		 FROM client_certs WHERE fingerprint_sha256 = $1`,
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

func (p *PostgresStore) RevokeClientCert(certID int64, now time.Time) error {
	_, err := p.db.Exec(
		`UPDATE client_certs SET status = 'revoked', revoked_at = $1 WHERE id = $2`,
		now, certID,
	)
	return err
}

func (p *PostgresStore) CreateEnrollToken(token EnrollToken) (*EnrollToken, error) {
	var out EnrollToken
	var used sql.NullTime
	var revoked sql.NullTime
	err := p.db.QueryRow(
		`INSERT INTO enroll_tokens (token_hash, client_id, expires_at, created_at)
		 VALUES ($1,$2,$3,$4)
		 RETURNING id, token_hash, client_id, expires_at, used_at, revoked_at, created_at`,
		token.TokenHash, token.ClientID, token.ExpiresAt, token.CreatedAt,
	).Scan(&out.ID, &out.TokenHash, &out.ClientID, &out.ExpiresAt, &used, &revoked, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	if used.Valid {
		out.UsedAt = used.Time
	}
	if revoked.Valid {
		out.RevokedAt = revoked.Time
	}
	return &out, nil
}

func (p *PostgresStore) ListEnrollTokens() ([]EnrollToken, error) {
	rows, err := p.db.Query(`
		SELECT id, token_hash, client_id, expires_at, used_at, revoked_at, created_at
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

func (p *PostgresStore) RevokeEnrollToken(id int64, now time.Time) error {
	_, err := p.db.Exec(
		`UPDATE enroll_tokens SET revoked_at = $1 WHERE id = $2 AND used_at IS NULL`,
		now, id,
	)
	return err
}

func (p *PostgresStore) ConsumeEnrollToken(tokenHash string, now time.Time) (*EnrollToken, error) {
	var token EnrollToken
	var used sql.NullTime
	var revoked sql.NullTime
	var expires time.Time
	var clientID int64

	tx, err := p.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	err = tx.QueryRow(
		`SELECT id, token_hash, client_id, expires_at, used_at, revoked_at, created_at
		 FROM enroll_tokens WHERE token_hash = $1 FOR UPDATE`,
		tokenHash,
	).Scan(&token.ID, &token.TokenHash, &clientID, &expires, &used, &revoked, &token.CreatedAt)
	if err != nil {
		return nil, err
	}

	token.ClientID = clientID
	token.ExpiresAt = expires
	if used.Valid {
		token.UsedAt = used.Time
	}
	if revoked.Valid {
		token.RevokedAt = revoked.Time
	}

	if used.Valid || revoked.Valid || token.ExpiresAt.Before(now) {
		return nil, errors.New("token invalid")
	}

	_, err = tx.Exec(`UPDATE enroll_tokens SET used_at = $1 WHERE id = $2`, now, token.ID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &token, nil
}

func (p *PostgresStore) InsertAuditEntry(entry AuditEntry) error {
	_, err := p.db.Exec(
		`INSERT INTO admin_audit_log (actor, action, target_type, target_id, metadata_json, created_at)
		 VALUES ($1,$2,$3,$4,$5::jsonb,$6)`,
		entry.Actor, entry.Action, entry.TargetType, entry.TargetID, entry.Metadata, entry.CreatedAt,
	)
	return err
}

func (p *PostgresStore) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := p.db.Query(
		`SELECT id, actor, action, target_type, target_id, metadata_json, created_at
		 FROM admin_audit_log ORDER BY id DESC LIMIT $1`,
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

func (p *PostgresStore) ListUserAudit(limit int) ([]UserAuditEntry, error) {
	rows, err := p.db.Query(
		`SELECT id, event_type, COALESCE(actor, ''), COALESCE(ip::text, ''), COALESCE(details::text, '{}'), created_at
		 FROM audit_log ORDER BY id DESC LIMIT $1`,
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
