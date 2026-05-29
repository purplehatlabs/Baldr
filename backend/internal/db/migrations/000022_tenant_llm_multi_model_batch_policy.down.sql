ALTER TABLE tenant_llm_configs
    DROP COLUMN IF EXISTS batch_mode,
    DROP COLUMN IF EXISTS default_model;
