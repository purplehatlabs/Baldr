-- Deduplicate existing findings before adding the unique constraint.
-- Keeps the most recent row (highest last_seen_at) per (manifest_id, osv_id,
-- package_name, package_version).
WITH ranked AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY manifest_id, osv_id, package_name, package_version
            ORDER BY last_seen_at DESC, first_seen_at DESC
        ) AS rn
    FROM findings
)
DELETE FROM findings
WHERE id IN (SELECT id FROM ranked WHERE rn > 1);

CREATE UNIQUE INDEX IF NOT EXISTS findings_manifest_osv_pkg_uniq
    ON findings (manifest_id, osv_id, package_name, package_version);
