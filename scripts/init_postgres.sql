-- APIGuard Enterprise v4.0 — PostgreSQL Schema
-- ================================================
-- Initializes the database schema for production deployment.
-- This script runs automatically via docker-entrypoint-initdb.d.

-- ── Scan History ────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_history (
    id SERIAL PRIMARY KEY,
    target TEXT NOT NULL,
    scan_date TIMESTAMP DEFAULT NOW(),
    risk_score FLOAT DEFAULT 0,
    critical INTEGER DEFAULT 0,
    high INTEGER DEFAULT 0,
    medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0,
    total_endpoints INTEGER DEFAULT 0,
    report_json JSONB,
    duration_seconds FLOAT DEFAULT 0,
    version TEXT DEFAULT '4.0'
);

CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_history(target);
CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_history(scan_date DESC);

-- ── Users ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    role TEXT DEFAULT 'individual',
    company_id TEXT,
    org_role TEXT DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ── Companies ───────────────────────────────────
CREATE TABLE IF NOT EXISTS companies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    join_code TEXT UNIQUE,
    created_by TEXT,
    plan TEXT DEFAULT 'free',
    created_at TIMESTAMP DEFAULT NOW()
);

-- ── API Keys ────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    scopes TEXT DEFAULT '*',
    created_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_apikeys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_apikeys_user ON api_keys(user_id);

-- ── Audit Log ───────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id TEXT,
    action TEXT,
    detail TEXT,
    ip_address TEXT,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);

-- ── Refresh Tokens ──────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT,
    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE
);

-- ── Remediation Findings ────────────────────────
CREATE TABLE IF NOT EXISTS remediation_findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER,
    vulnerability_type TEXT,
    severity TEXT,
    endpoint TEXT,
    status TEXT DEFAULT 'open',
    assignee TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON remediation_findings(status);

-- ── Scan Schedules ──────────────────────────────
CREATE TABLE IF NOT EXISTS scan_schedules (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    target_url TEXT NOT NULL,
    cron_expr TEXT DEFAULT '0 3 * * *',
    modules TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    last_run TIMESTAMP,
    next_run TIMESTAMP
);

-- ── Custom Rules ────────────────────────────────
CREATE TABLE IF NOT EXISTS custom_rules (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    yaml_content TEXT NOT NULL,
    severity TEXT DEFAULT 'MEDIUM',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ── Rate Limiter ────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limits (
    id SERIAL PRIMARY KEY,
    client_ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    request_count INTEGER DEFAULT 0,
    window_start TIMESTAMP DEFAULT NOW(),
    blocked_until TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ratelimit_ip ON rate_limits(client_ip, endpoint);
