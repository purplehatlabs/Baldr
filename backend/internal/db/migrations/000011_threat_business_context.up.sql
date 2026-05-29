ALTER TABLE repositories
    ADD COLUMN is_internet_exposed BOOLEAN,
    ADD COLUMN exposure_source VARCHAR(50)
        CHECK (exposure_source IN ('manual', 'auto_discovery')),
    ADD COLUMN exposure_updated_at TIMESTAMPTZ,
    ADD COLUMN asset_criticality VARCHAR(50) NOT NULL DEFAULT 'medium'
        CHECK (asset_criticality IN ('low', 'medium', 'high', 'critical')),
    ADD COLUMN data_sensitivity VARCHAR(50) NOT NULL DEFAULT 'internal'
        CHECK (data_sensitivity IN ('public', 'internal', 'confidential', 'restricted')),
    ADD COLUMN environment VARCHAR(50) NOT NULL DEFAULT 'prod'
        CHECK (environment IN ('dev', 'staging', 'prod'));

ALTER TABLE findings
    ADD COLUMN epss_score NUMERIC(7, 6),
    ADD COLUMN epss_percentile NUMERIC(7, 6),
    ADD COLUMN kev_listed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN threat_updated_at TIMESTAMPTZ;

CREATE INDEX idx_repositories_exposure_pending
    ON repositories (org_id)
    WHERE is_internet_exposed IS NULL;

CREATE INDEX idx_findings_threat_updated_at
    ON findings (threat_updated_at DESC);
