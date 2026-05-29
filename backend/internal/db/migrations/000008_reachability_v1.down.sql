DROP INDEX IF EXISTS idx_findings_status_severity_reachability;
DROP INDEX IF EXISTS idx_findings_reachability_status;

ALTER TABLE findings
    DROP COLUMN IF EXISTS reachability_analyzed_at,
    DROP COLUMN IF EXISTS reachability_evidence_json,
    DROP COLUMN IF EXISTS reachability_confidence,
    DROP COLUMN IF EXISTS reachability_status;
