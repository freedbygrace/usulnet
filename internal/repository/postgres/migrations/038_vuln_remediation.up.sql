-- Migration 038: CVE Remediation Workflow — Phase 2
-- Adds resolution evidence, user assignment, and weekly trend tracking.

ALTER TABLE tracked_vulnerabilities
    ADD COLUMN IF NOT EXISTS resolution_notes TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS resolved_scan_id UUID,
    ADD COLUMN IF NOT EXISTS assignee_id UUID;

-- Index for SLA breach queries (status + deadline)
CREATE INDEX IF NOT EXISTS idx_tracked_vuln_sla
    ON tracked_vulnerabilities (sla_deadline)
    WHERE status NOT IN ('resolved', 'accepted_risk') AND sla_deadline IS NOT NULL;

-- Index for assignee-based queries
CREATE INDEX IF NOT EXISTS idx_tracked_vuln_assignee
    ON tracked_vulnerabilities (assignee_id)
    WHERE assignee_id IS NOT NULL;

-- Weekly trend materialized as a view for dashboard queries
CREATE OR REPLACE VIEW vuln_weekly_trend AS
SELECT
    date_trunc('week', detected_at)::date AS week,
    COUNT(*) FILTER (WHERE TRUE)           AS opened,
    COUNT(*) FILTER (WHERE resolved_at IS NOT NULL
        AND date_trunc('week', resolved_at) = date_trunc('week', detected_at)) AS resolved_same_week
FROM tracked_vulnerabilities
GROUP BY date_trunc('week', detected_at)
ORDER BY week DESC
LIMIT 26;
