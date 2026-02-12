-- Migration 026 Down: Enterprise Hardening rollback

DROP TABLE IF EXISTS runtime_baselines CASCADE;
DROP TABLE IF EXISTS runtime_security_events CASCADE;
DROP TABLE IF EXISTS runtime_security_rules CASCADE;

DROP TABLE IF EXISTS image_trust_policies CASCADE;
DROP TABLE IF EXISTS image_attestations CASCADE;
DROP TABLE IF EXISTS image_signatures CASCADE;

DROP TABLE IF EXISTS opa_evaluation_results CASCADE;
DROP TABLE IF EXISTS opa_policies CASCADE;

DROP TABLE IF EXISTS compliance_evidence CASCADE;
DROP TABLE IF EXISTS compliance_assessments CASCADE;
DROP TABLE IF EXISTS compliance_controls CASCADE;
DROP TABLE IF EXISTS compliance_frameworks CASCADE;

DROP TABLE IF EXISTS log_search_queries CASCADE;
DROP TABLE IF EXISTS aggregated_logs CASCADE;

DROP TABLE IF EXISTS dashboard_widgets CASCADE;
DROP TABLE IF EXISTS dashboard_layouts CASCADE;
