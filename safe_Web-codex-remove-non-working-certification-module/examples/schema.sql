CREATE TABLE users (
    id                  BIGSERIAL PRIMARY KEY,
    client_id           BIGINT REFERENCES clients(id),
    username            TEXT UNIQUE NOT NULL,
    password_hash       TEXT NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE admin_users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE clients (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE client_certs (
    id                 BIGSERIAL PRIMARY KEY,
    client_id          BIGINT NOT NULL REFERENCES clients(id),
    serial             TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    not_before         TIMESTAMPTZ NOT NULL,
    not_after          TIMESTAMPTZ NOT NULL,
    status             TEXT NOT NULL DEFAULT 'active',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at         TIMESTAMPTZ
);

CREATE TABLE enroll_tokens (
    id         BIGSERIAL PRIMARY KEY,
    token_hash TEXT NOT NULL,
    client_id  BIGINT NOT NULL REFERENCES clients(id),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE whitelist (
    id         BIGSERIAL PRIMARY KEY,
    value      TEXT NOT NULL,
    owner_type TEXT NOT NULL,
    owner_id   BIGINT NOT NULL DEFAULT 0,
    label      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE login_attempts (
    id         BIGSERIAL PRIMARY KEY,
    ip         INET NOT NULL,
    username   TEXT,
    success    BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent TEXT
);

CREATE TABLE ip_bans (
    ip           INET PRIMARY KEY,
    banned_until TIMESTAMPTZ NOT NULL,
    reason       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor      TEXT,
    ip         INET,
    details    JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE admin_audit_log (
    id           BIGSERIAL PRIMARY KEY,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    metadata_json JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_client ON users (client_id);
CREATE INDEX idx_login_attempts_ip_time ON login_attempts (ip, created_at DESC);
CREATE INDEX idx_login_attempts_user_time ON login_attempts (username, created_at DESC);
CREATE INDEX idx_ip_bans_until ON ip_bans (banned_until);
CREATE INDEX idx_audit_log_time ON audit_log (created_at DESC);
CREATE INDEX idx_admin_audit_log_time ON admin_audit_log (created_at DESC);
CREATE INDEX idx_client_certs_fingerprint ON client_certs (fingerprint_sha256);
CREATE INDEX idx_enroll_tokens_hash ON enroll_tokens (token_hash);
CREATE INDEX idx_whitelist_value ON whitelist (value);
