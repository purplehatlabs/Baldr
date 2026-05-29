DROP INDEX IF EXISTS idx_findings_status_triage;
DROP INDEX IF EXISTS idx_findings_triage_status;

ALTER TABLE findings
    DROP COLUMN IF EXISTS triage_decision_source,
    DROP COLUMN IF EXISTS triage_decided_by_user_id,
    DROP COLUMN IF EXISTS triage_decided_at,
    DROP COLUMN IF EXISTS triage_status;
