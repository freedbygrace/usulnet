-- ============================================================================
-- 030_backup_drop_legacy_columns: Restore legacy columns
-- ============================================================================

ALTER TABLE backups ADD COLUMN IF NOT EXISTS name VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE backups ADD COLUMN IF NOT EXISTS target_type VARCHAR(50) NOT NULL DEFAULT '';
ALTER TABLE backups ADD COLUMN IF NOT EXISTS storage_path TEXT;
ALTER TABLE backups ADD COLUMN IF NOT EXISTS storage_type VARCHAR(50) NOT NULL DEFAULT 'local';

ALTER TABLE backup_schedules ADD COLUMN IF NOT EXISTS name VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE backup_schedules ADD COLUMN IF NOT EXISTS target_type VARCHAR(50) NOT NULL DEFAULT '';
ALTER TABLE backup_schedules ADD COLUMN IF NOT EXISTS storage_type VARCHAR(50) NOT NULL DEFAULT 'local';
ALTER TABLE backup_schedules ADD COLUMN IF NOT EXISTS retention_count INTEGER NOT NULL DEFAULT 5;
