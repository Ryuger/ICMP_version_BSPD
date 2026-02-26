package store

import "time"

type User struct {
	ID                int64
	ClientID          int64
	Username          string
	PasswordHash      string
	IsActive          bool
	PasswordChangedAt time.Time
}

type AdminUser struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	LastLoginAt  time.Time
}

type Client struct {
	ID        int64
	Name      string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type ClientCert struct {
	ID                int64
	ClientID          int64
	Serial            string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
	Status            string
	CreatedAt         time.Time
	RevokedAt         time.Time
}

type EnrollToken struct {
	ID        int64
	ClientID  int64
	TokenHash string
	ExpiresAt time.Time
	UsedAt    time.Time
	RevokedAt time.Time
	CreatedAt time.Time
}

type WhitelistEntry struct {
	ID        int64
	Value     string
	OwnerType string
	OwnerID   int64
	Label     string
	CreatedAt time.Time
}

type AuditEntry struct {
	ID         int64
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	Metadata   string
	CreatedAt  time.Time
}

type UserAuditEntry struct {
	ID        int64
	EventType string
	Actor     string
	IP        string
	Details   string
	CreatedAt time.Time
}

type Store interface {
	IsBanned(ip string, now time.Time) (bool, error)
	IsWhitelisted(ip string) (bool, error)
	ListWhitelist() ([]WhitelistEntry, error)
	AddWhitelist(entry WhitelistEntry) error
	DeleteWhitelist(id int64) error

	GetUser(username string) (*User, error)
	CreateUser(clientID int64, username, passwordHash string, now time.Time) (*User, error)
	ListUsersByClient(clientID int64) ([]User, error)
	InsertAttempt(ip, username string, success bool, now time.Time) error
	CheckConsecutiveFailures(ip string, window time.Duration, limit int, now time.Time) (bool, error)
	UpsertBan(ip string, ttl time.Duration, reason string, now time.Time) error
	InsertAudit(eventType, actor, ip, details string, now time.Time) error
	UpdatePassword(username, passwordHash string, changedAt time.Time) error

	GetAdminUser(username string) (*AdminUser, error)
	UpdateAdminLogin(username string, lastLogin time.Time) error
	CreateClient(name string, now time.Time) (*Client, error)
	ListClients() ([]Client, error)
	GetClient(id int64) (*Client, error)
	SetClientStatus(id int64, status string, now time.Time) error
	InsertClientCert(cert ClientCert) error
	ListClientCerts(clientID int64) ([]ClientCert, error)
	FindClientCertByFingerprint(fingerprint string) (*ClientCert, error)
	RevokeClientCert(certID int64, now time.Time) error
	CreateEnrollToken(token EnrollToken) (*EnrollToken, error)
	ListEnrollTokens() ([]EnrollToken, error)
	RevokeEnrollToken(id int64, now time.Time) error
	ConsumeEnrollToken(tokenHash string, now time.Time) (*EnrollToken, error)
	InsertAuditEntry(entry AuditEntry) error
	ListAudit(limit int) ([]AuditEntry, error)
	ListUserAudit(limit int) ([]UserAuditEntry, error)
}
