-- At most one pending or running scan job per repository (idempotent enqueue).
-- Existing dev data may have multiple active jobs per repo; keep the newest only.
WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY repo_id
               ORDER BY created_at DESC, id DESC
           ) AS rn
    FROM scan_jobs
    WHERE status IN ('pending', 'running')
)
UPDATE scan_jobs j
SET status = 'failed',
    completed_at = NOW(),
    error_msg = 'migration: superseded duplicate active scan job'
FROM ranked r
WHERE j.id = r.id AND r.rn > 1;

CREATE UNIQUE INDEX idx_scan_jobs_one_active_per_repo
    ON scan_jobs (repo_id)
    WHERE status IN ('pending', 'running');
