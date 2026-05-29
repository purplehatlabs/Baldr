ALTER TABLE tenant_llm_configs
    ADD COLUMN agentic_model TEXT,
    ADD COLUMN translation_model TEXT,
    ADD COLUMN batch_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE finding_analyses
    ADD COLUMN llm_dispatch_mode VARCHAR(50) NOT NULL DEFAULT 'realtime'
        CHECK (llm_dispatch_mode IN ('realtime', 'batch_pending', 'batch_done', 'batch_fallback')),
    ADD COLUMN llm_batch_id TEXT,
    ADD COLUMN llm_dispatch_meta JSONB;

CREATE INDEX idx_finding_analyses_batch_pending
    ON finding_analyses (llm_dispatch_mode)
    WHERE llm_dispatch_mode = 'batch_pending';
