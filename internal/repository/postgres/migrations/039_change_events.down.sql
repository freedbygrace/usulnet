-- Rollback migration 039: Drop change_events table and related objects

DROP TRIGGER IF EXISTS change_events_search_update ON change_events;
DROP FUNCTION IF EXISTS change_events_search_trigger();
DROP FUNCTION IF EXISTS cleanup_old_change_events(INTEGER);
DROP TABLE IF EXISTS change_events;
