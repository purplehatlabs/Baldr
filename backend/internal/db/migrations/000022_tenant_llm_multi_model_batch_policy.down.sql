ALTER TABLE tenant_llm_configs
    DROP COLUMN IF EXISTS batch_mode,
    DROP COLUMN IF EXISTS batch_enabled,
    DROP COLUMN IF EXISTS translation_model,
    DROP COLUMN IF EXISTS agentic_model,
    DROP COLUMN IF EXISTS default_model;
