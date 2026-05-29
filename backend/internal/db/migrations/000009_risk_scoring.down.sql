DROP INDEX IF EXISTS idx_findings_sla_breached;
DROP INDEX IF EXISTS idx_findings_status_risk_score;
DROP INDEX IF EXISTS idx_findings_risk_score;

ALTER TABLE findings
    DROP COLUMN IF EXISTS is_sla_breached,
    DROP COLUMN IF EXISTS sla_due_at,
    DROP COLUMN IF EXISTS risk_scored_at,
    DROP COLUMN IF EXISTS risk_factors_json,
    DROP COLUMN IF EXISTS risk_tier,
    DROP COLUMN IF EXISTS risk_score;
