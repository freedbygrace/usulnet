-- Rollback migration 041: Drop cost/resource optimization tables and functions

DROP FUNCTION IF EXISTS cleanup_old_usage_samples(INTEGER);
DROP TABLE IF EXISTS resource_recommendations;
DROP TABLE IF EXISTS resource_usage_daily;
DROP TABLE IF EXISTS resource_usage_hourly;
DROP TABLE IF EXISTS resource_usage_samples;
