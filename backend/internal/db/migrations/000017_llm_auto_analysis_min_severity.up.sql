ALTER TABLE tenant_llm_configs
    ADD COLUMN auto_analysis_min_severity TEXT NOT NULL DEFAULT 'high'
        CHECK (auto_analysis_min_severity IN ('critical', 'high', 'medium'));
