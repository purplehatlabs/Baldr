ALTER TABLE tenant_llm_configs
    ADD COLUMN IF NOT EXISTS default_model TEXT,
    ADD COLUMN IF NOT EXISTS batch_mode TEXT NOT NULL DEFAULT 'realtime'
        CHECK (batch_mode IN ('realtime', 'prefer_batch'));

UPDATE tenant_llm_configs
SET default_model = model
WHERE default_model IS NULL;

ALTER TABLE tenant_llm_configs
    ALTER COLUMN default_model SET NOT NULL;
