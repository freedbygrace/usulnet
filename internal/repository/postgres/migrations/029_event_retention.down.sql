-- 029_event_retention.down.sql
DROP FUNCTION IF EXISTS cleanup_old_runtime_security_events(INTEGER);
DROP FUNCTION IF EXISTS cleanup_old_alert_events(INTEGER);
