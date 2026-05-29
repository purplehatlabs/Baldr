DROP INDEX IF EXISTS idx_findings_source_engine;
DROP INDEX IF EXISTS idx_findings_finding_type;

ALTER TABLE findings DROP COLUMN IF EXISTS source_engine;
ALTER TABLE findings DROP COLUMN IF EXISTS finding_type;
