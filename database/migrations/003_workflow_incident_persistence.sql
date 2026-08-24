-- Durable workflow, incident, finding and evidence persistence.
CREATE TABLE IF NOT EXISTS workflow_checkpoints (
    incident_id UUID PRIMARY KEY,
    state JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'paused',
    version BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id UUID PRIMARY KEY,
    source VARCHAR(64) NOT NULL,
    severity VARCHAR(32),
    service VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'open',
    summary TEXT,
    started_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incident_findings (
    id BIGSERIAL PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    agent VARCHAR(128),
    finding_type VARCHAR(128),
    statement TEXT,
    evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incident_evidence (
    evidence_id VARCHAR(255) PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    evidence_type VARCHAR(64) NOT NULL,
    source VARCHAR(128) NOT NULL,
    reference TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incident_findings_incident ON incident_findings(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_evidence_incident ON incident_evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_workflow_checkpoints_status ON workflow_checkpoints(status);
