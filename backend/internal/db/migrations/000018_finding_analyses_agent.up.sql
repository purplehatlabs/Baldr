ALTER TABLE finding_analyses
    ADD COLUMN agent_trace_json JSONB,
    ADD COLUMN vulnerable_code_paths_json JSONB;
