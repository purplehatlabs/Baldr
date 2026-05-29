ALTER TABLE findings
    ADD COLUMN risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0,
    ADD COLUMN risk_tier VARCHAR(50) NOT NULL DEFAULT 'low'
        CHECK (risk_tier IN ('critical', 'high', 'medium', 'low')),
    ADD COLUMN risk_factors_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN risk_scored_at TIMESTAMPTZ,
    ADD COLUMN sla_due_at TIMESTAMPTZ,
    ADD COLUMN is_sla_breached BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX idx_findings_risk_score ON findings (risk_score DESC);
CREATE INDEX idx_findings_status_risk_score ON findings (status, risk_score DESC);
CREATE INDEX idx_findings_sla_breached ON findings (is_sla_breached) WHERE is_sla_breached = TRUE;
