-- Governance persistence required by MASTER.md.
-- Run after the baseline schema migration.

CREATE TABLE IF NOT EXISTS approvals (
    approval_id UUID PRIMARY KEY,
    incident_id UUID NULL,
    action TEXT NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    approver VARCHAR(255) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMPTZ NULL,
    rejected_at TIMESTAMPTZ NULL,
    CONSTRAINT approvals_status_ck CHECK (status IN ('pending','approved','rejected','expired'))
);
CREATE INDEX IF NOT EXISTS ix_approvals_incident_id ON approvals(incident_id);
CREATE INDEX IF NOT EXISTS ix_approvals_status ON approvals(status);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id UUID PRIMARY KEY,
    event_type VARCHAR(120) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    incident_id UUID NULL,
    action TEXT NULL,
    status VARCHAR(50) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_audit_events_incident_id ON audit_events(incident_id);
CREATE INDEX IF NOT EXISTS ix_audit_events_created_at ON audit_events(created_at);

CREATE TABLE IF NOT EXISTS runbooks (
    runbook_id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    version VARCHAR(50) NOT NULL,
    owner VARCHAR(255) NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    preconditions JSONB NOT NULL DEFAULT '[]'::jsonb,
    steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    timeout_seconds INTEGER NOT NULL DEFAULT 300,
    rollback_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
