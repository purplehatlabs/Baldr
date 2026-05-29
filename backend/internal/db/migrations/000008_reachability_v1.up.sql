ALTER TABLE findings
    ADD COLUMN reachability_status VARCHAR(50) NOT NULL DEFAULT 'unknown'
        CHECK (reachability_status IN ('reachable', 'unknown', 'unreachable')),
    ADD COLUMN reachability_confidence NUMERIC(3, 2),
    ADD COLUMN reachability_evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN reachability_analyzed_at TIMESTAMPTZ;

CREATE INDEX idx_findings_reachability_status ON findings (reachability_status);
CREATE INDEX idx_findings_status_severity_reachability
    ON findings (status, severity, reachability_status);
