ALTER TABLE finding_analyses
    DROP COLUMN IF EXISTS agent_trace_json,
    DROP COLUMN IF EXISTS vulnerable_code_paths_json;
