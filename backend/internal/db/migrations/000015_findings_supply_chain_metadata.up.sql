ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS finding_type VARCHAR(50) NOT NULL DEFAULT 'vulnerability'
    CHECK (finding_type IN ('vulnerability', 'malicious_package', 'suspicious_behavior'));

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS source_engine VARCHAR(50) NOT NULL DEFAULT 'osv'
    CHECK (source_engine IN ('osv', 'dataset', 'guarddog', 'openssf_pa', 'manual'));

CREATE INDEX IF NOT EXISTS idx_findings_finding_type ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_source_engine ON findings(source_engine);
