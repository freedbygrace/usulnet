-- Rollback migration 040: Drop drift detection tables

DROP TABLE IF EXISTS drift_detections;
DROP TABLE IF EXISTS configuration_snapshots;
