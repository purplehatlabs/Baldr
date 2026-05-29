DROP INDEX IF EXISTS idx_integration_configs_tenant_type;
DROP INDEX IF EXISTS idx_saved_views_tenant_user;
DROP INDEX IF EXISTS idx_finding_audit_logs_tenant_finding_created;
DROP INDEX IF EXISTS idx_finding_exceptions_expires_at;
DROP INDEX IF EXISTS idx_finding_exceptions_tenant_finding;
DROP INDEX IF EXISTS idx_policy_rules_tenant_policy;
DROP INDEX IF EXISTS idx_policies_tenant_id;

DROP TABLE IF EXISTS integration_configs;
DROP TABLE IF EXISTS saved_views;
DROP TABLE IF EXISTS finding_audit_logs;
DROP TABLE IF EXISTS finding_exceptions;
DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS policies;
