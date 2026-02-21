-- Rollback migration 038: CVE Remediation Workflow
DROP VIEW IF EXISTS vuln_weekly_trend;
DROP INDEX IF EXISTS idx_tracked_vuln_assignee;
DROP INDEX IF EXISTS idx_tracked_vuln_sla;

ALTER TABLE tracked_vulnerabilities
    DROP COLUMN IF EXISTS resolution_notes,
    DROP COLUMN IF EXISTS resolved_scan_id,
    DROP COLUMN IF EXISTS assignee_id;
