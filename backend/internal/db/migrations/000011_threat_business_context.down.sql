DROP INDEX IF EXISTS idx_findings_threat_updated_at;
DROP INDEX IF EXISTS idx_repositories_exposure_pending;

ALTER TABLE findings
    DROP COLUMN IF EXISTS threat_updated_at,
    DROP COLUMN IF EXISTS kev_listed,
    DROP COLUMN IF EXISTS epss_percentile,
    DROP COLUMN IF EXISTS epss_score;

ALTER TABLE repositories
    DROP COLUMN IF EXISTS environment,
    DROP COLUMN IF EXISTS data_sensitivity,
    DROP COLUMN IF EXISTS asset_criticality,
    DROP COLUMN IF EXISTS exposure_updated_at,
    DROP COLUMN IF EXISTS exposure_source,
    DROP COLUMN IF EXISTS is_internet_exposed;
