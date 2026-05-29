ALTER TABLE finding_analyses
    DROP COLUMN IF EXISTS reasoning_pt_br,
    DROP COLUMN IF EXISTS exploitation_path_pt_br,
    DROP COLUMN IF EXISTS remediation_path_pt_br;
