-- Rollback 032_retention_security_jobs
DROP FUNCTION IF EXISTS cleanup_old_container_logs(INTEGER);
DROP FUNCTION IF EXISTS cleanup_old_completed_jobs(INTEGER);
DROP FUNCTION IF EXISTS cleanup_old_security_scans(INTEGER);
