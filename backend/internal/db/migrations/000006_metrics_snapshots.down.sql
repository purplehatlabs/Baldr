DROP INDEX IF EXISTS idx_team_metrics_daily_tenant_team_date;
DROP INDEX IF EXISTS idx_team_metrics_daily_tenant_date;
DROP INDEX IF EXISTS idx_repo_metrics_daily_tenant_repo_date;
DROP INDEX IF EXISTS idx_repo_metrics_daily_tenant_date;
DROP INDEX IF EXISTS idx_tenant_metrics_daily_tenant_date;

DROP TABLE IF EXISTS team_metrics_daily;
DROP TABLE IF EXISTS repo_metrics_daily;
DROP TABLE IF EXISTS tenant_metrics_daily;
