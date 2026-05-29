DROP INDEX IF EXISTS idx_findings_last_seen_at;
DROP INDEX IF EXISTS idx_findings_tenant_severity;
DROP INDEX IF EXISTS idx_findings_tenant_status;
DROP INDEX IF EXISTS idx_findings_tenant_source_engine;
DROP INDEX IF EXISTS idx_findings_tenant_id;

ALTER TABLE findings DROP COLUMN IF EXISTS evidence_json;
ALTER TABLE findings DROP COLUMN IF EXISTS business_impact;
ALTER TABLE findings DROP COLUMN IF EXISTS created_by_user_id;
ALTER TABLE findings DROP COLUMN IF EXISTS reported_at;
ALTER TABLE findings DROP COLUMN IF EXISTS external_reference;
ALTER TABLE findings DROP COLUMN IF EXISTS external_source;

DELETE FROM findings WHERE manifest_id IS NULL OR scan_job_id IS NULL;

ALTER TABLE findings ALTER COLUMN manifest_id SET NOT NULL;
ALTER TABLE findings ALTER COLUMN scan_job_id SET NOT NULL;

ALTER TABLE findings DROP COLUMN IF EXISTS tenant_id;
