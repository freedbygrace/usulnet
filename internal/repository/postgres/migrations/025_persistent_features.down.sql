-- ============================================================================
-- 025_persistent_features: Reverse migration
-- ============================================================================

DROP TABLE IF EXISTS tracked_vulnerabilities CASCADE;
DROP TABLE IF EXISTS container_templates CASCADE;
DROP TABLE IF EXISTS resource_quotas CASCADE;
DROP TABLE IF EXISTS gitops_deployments CASCADE;
DROP TABLE IF EXISTS gitops_pipelines CASCADE;
DROP TABLE IF EXISTS maintenance_windows CASCADE;
DROP TABLE IF EXISTS lifecycle_history CASCADE;
DROP TABLE IF EXISTS lifecycle_policies CASCADE;
DROP TABLE IF EXISTS managed_secrets CASCADE;
DROP TABLE IF EXISTS compliance_violations CASCADE;
DROP TABLE IF EXISTS compliance_policies CASCADE;
