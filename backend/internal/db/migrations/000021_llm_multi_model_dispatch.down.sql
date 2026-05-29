DROP INDEX IF EXISTS idx_finding_analyses_batch_pending;

ALTER TABLE finding_analyses
    DROP COLUMN IF EXISTS llm_dispatch_meta,
    DROP COLUMN IF EXISTS llm_batch_id,
    DROP COLUMN IF EXISTS llm_dispatch_mode;

ALTER TABLE tenant_llm_configs
    DROP COLUMN IF EXISTS batch_enabled,
    DROP COLUMN IF EXISTS translation_model,
    DROP COLUMN IF EXISTS agentic_model;
