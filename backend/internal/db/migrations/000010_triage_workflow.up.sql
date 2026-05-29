ALTER TABLE findings
    ADD COLUMN triage_status VARCHAR(50) NOT NULL DEFAULT 'new'
        CHECK (triage_status IN ('new', 'needs_review', 'confirmed', 'dismissed')),
    ADD COLUMN triage_decided_at TIMESTAMPTZ,
    ADD COLUMN triage_decided_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN triage_decision_source VARCHAR(50)
        CHECK (triage_decision_source IS NULL OR triage_decision_source IN ('auto_ai', 'manual', 'system'));

CREATE INDEX idx_findings_triage_status ON findings (triage_status);
CREATE INDEX idx_findings_status_triage ON findings (status, triage_status);

UPDATE findings SET triage_status = 'dismissed' WHERE status = 'suppressed';
UPDATE findings SET triage_status = 'confirmed' WHERE status = 'fixed';

UPDATE findings f
SET triage_status = 'needs_review'
FROM (
    SELECT DISTINCT ON (finding_id)
        finding_id,
        criticality_verdict
    FROM finding_analyses
    WHERE analysis_status = 'completed'
    ORDER BY finding_id, created_at DESC
) fa
WHERE f.id = fa.finding_id
  AND f.status = 'open'
  AND fa.criticality_verdict = 'needs_human_review';

UPDATE findings f
SET
    triage_status = 'confirmed',
    triage_decision_source = 'auto_ai',
    triage_decided_at = NOW()
FROM (
    SELECT DISTINCT ON (fa.finding_id)
        fa.finding_id,
        fa.criticality_verdict,
        fa.confidence
    FROM finding_analyses fa
    WHERE fa.analysis_status = 'completed'
    ORDER BY fa.finding_id, fa.created_at DESC
) latest
WHERE f.id = latest.finding_id
  AND f.status = 'open'
  AND latest.criticality_verdict = 'true_critical'
  AND f.reachability_status = 'reachable'
  AND latest.confidence >= 0.8;
