DROP INDEX IF EXISTS idx_package_dynamic_runs_package;
DROP INDEX IF EXISTS idx_package_dynamic_runs_tenant_status;
DROP INDEX IF EXISTS idx_package_dynamic_runs_tenant_signal_engine;
DROP TABLE IF EXISTS package_dynamic_analysis_runs;

DROP INDEX IF EXISTS idx_supply_chain_signals_package;
DROP INDEX IF EXISTS idx_supply_chain_signals_indicator;
DROP INDEX IF EXISTS idx_supply_chain_signals_repo_manifest;
DROP INDEX IF EXISTS idx_supply_chain_signals_tenant_status;
DROP TABLE IF EXISTS supply_chain_signals;

DROP INDEX IF EXISTS idx_package_inventory_finding_id;
DROP INDEX IF EXISTS idx_package_inventory_pkg;
DROP INDEX IF EXISTS idx_package_inventory_tenant_repo;
DROP TABLE IF EXISTS package_inventory;

DROP INDEX IF EXISTS idx_malicious_indicators_last_synced;
DROP INDEX IF EXISTS idx_malicious_indicators_pkg;
DROP INDEX IF EXISTS idx_malicious_indicators_external_id;
DROP TABLE IF EXISTS malicious_package_indicators;
