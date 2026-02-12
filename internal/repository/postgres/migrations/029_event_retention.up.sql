-- 029_event_retention.up.sql
-- Adds retention cleanup functions for runtime_security_events and alert_events tables.
-- These tables previously had no automated cleanup, causing unbounded growth.

-- Cleanup old runtime security events (default: 30 days)
CREATE OR REPLACE FUNCTION cleanup_old_runtime_security_events(retention_days INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    rows_deleted INTEGER;
BEGIN
    DELETE FROM runtime_security_events
    WHERE detected_at < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    RETURN rows_deleted;
END;
$$ LANGUAGE plpgsql;

-- Cleanup old alert events (default: 90 days)
CREATE OR REPLACE FUNCTION cleanup_old_alert_events(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    rows_deleted INTEGER;
BEGIN
    DELETE FROM alert_events
    WHERE fired_at < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    RETURN rows_deleted;
END;
$$ LANGUAGE plpgsql;
