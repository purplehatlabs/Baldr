# Risk Scoring v2 - Metrics and Experiment

## What changed

- Risk now uses three explainable pillars:
  - `technical_score` (severity, CVSS, reachability, exploitability, age, fix availability)
  - `threat_score` (EPSS + CISA KEV)
  - `business_score` (internet exposure, asset criticality, data sensitivity, environment)
- Final score formula:
  - `final_risk_score = 0.45 * technical + 0.35 * threat + 0.20 * business`
- Tier overrides:
  - If `kev_listed=true` and finding is reachable, minimum tier is `high`
  - If finding is `critical`, unreachable, with low threat and no KEV, downgrade one tier (never below `medium`)
- Scan gate is enforced in all triggers: repos must have explicit `is_internet_exposed` (`true` or `false`).

## Product validation metrics

- **Exposure coverage:** `% repositories with is_internet_exposed != null`
  - Target: 100%
- **Gate compliance:** `# scans blocked_missing_exposure / # scan attempts`
  - Target: initial spike during rollout, then trend to 0 blocked attempts
- **Top-20 precision:** `% top-20 findings triaged as confirmed`
  - Compare v1 baseline vs v2
- **Operational noise:** `% top-ranked findings dismissed as not actionable`
  - Target: decrease
- **MTTR on exploitable high-risk findings**
  - Target: decrease

## Suggested A/B experiment

- **Control:** previous ranking (risk v1)
- **Treatment:** hybrid ranking (risk v2)
- **Population split:** tenant-level split (50/50) or alternating weekly windows for the same tenant
- **Primary success metric:** top-20 precision uplift
- **Secondary metrics:** MTTR, dismiss rate, breach rate of SLA for confirmed high/critical
- **Run length:** at least 2 full scan cycles per tenant segment

## Minimal SQL checks

```sql
-- Coverage of exposure classification
SELECT
  COUNT(*) FILTER (WHERE is_internet_exposed IS NOT NULL) * 100.0 / NULLIF(COUNT(*), 0) AS coverage_pct
FROM repositories;

-- Findings with explainable factors and pillar presence
SELECT
  COUNT(*) FILTER (WHERE jsonb_typeof(risk_factors_json) = 'array') AS with_factors,
  COUNT(*) AS total
FROM findings;
```
