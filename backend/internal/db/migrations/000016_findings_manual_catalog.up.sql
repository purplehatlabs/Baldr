ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

UPDATE findings f
SET tenant_id = o.tenant_id
FROM manifests m
JOIN repositories r ON r.id = m.repo_id
JOIN organizations o ON o.id = r.org_id
WHERE f.manifest_id = m.id
  AND f.tenant_id IS NULL;

ALTER TABLE findings
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE findings
    ALTER COLUMN scan_job_id DROP NOT NULL;

ALTER TABLE findings
    ALTER COLUMN manifest_id DROP NOT NULL;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS external_source VARCHAR(255) NOT NULL DEFAULT '';

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS external_reference VARCHAR(255) NOT NULL DEFAULT '';

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS reported_at TIMESTAMPTZ;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS business_impact TEXT NOT NULL DEFAULT '';

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS evidence_json JSONB NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_source_engine ON findings(tenant_id, source_engine);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_status ON findings(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_severity ON findings(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen_at ON findings(last_seen_at DESC);
