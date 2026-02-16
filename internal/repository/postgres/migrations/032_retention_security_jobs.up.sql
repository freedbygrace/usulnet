-- ============================================================================
-- 032_retention_security_jobs: Add retention cleanup for security_scans and
-- completed jobs tables, which previously had no automated cleanup.
-- ============================================================================

-- Cleanup old security scans (default: 90 days)
-- Keeps the latest scan per container and deletes older ones beyond retention.
CREATE OR REPLACE FUNCTION cleanup_old_security_scans(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    rows_deleted INTEGER;
BEGIN
    -- Delete scans older than retention period, but always keep the most
    -- recent scan per (host_id, container_id) for historical reference.
    DELETE FROM security_scans
    WHERE completed_at < NOW() - (retention_days || ' days')::INTERVAL
      AND id NOT IN (
          SELECT DISTINCT ON (host_id, container_id) id
          FROM security_scans
          ORDER BY host_id, container_id, completed_at DESC
      );
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    RETURN rows_deleted;
END;
$$ LANGUAGE plpgsql;

-- Cleanup old completed/failed/cancelled jobs (default: 30 days)
CREATE OR REPLACE FUNCTION cleanup_old_completed_jobs(retention_days INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    rows_deleted INTEGER;
BEGIN
    DELETE FROM jobs
    WHERE status IN ('completed', 'failed', 'cancelled')
      AND completed_at < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    RETURN rows_deleted;
END;
$$ LANGUAGE plpgsql;

-- Cleanup old container logs (default: 14 days)
CREATE OR REPLACE FUNCTION cleanup_old_container_logs(retention_days INTEGER DEFAULT 14)
RETURNS INTEGER AS $$
DECLARE
    rows_deleted INTEGER;
BEGIN
    DELETE FROM container_logs
    WHERE timestamp < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    RETURN rows_deleted;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_old_security_scans IS 'Delete security_scans older than N days (default 90), keeping latest per container';
COMMENT ON FUNCTION cleanup_old_completed_jobs IS 'Delete completed/failed/cancelled jobs older than N days (default 30)';
COMMENT ON FUNCTION cleanup_old_container_logs IS 'Delete container_logs older than N days (default 14)';
