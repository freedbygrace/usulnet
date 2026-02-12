-- ============================================================================
-- 028_backup_schema_sync (rollback)
-- ============================================================================

ALTER TABLE backups DROP COLUMN IF EXISTS trigger;
ALTER TABLE backups DROP COLUMN IF EXISTS path;
ALTER TABLE backups DROP COLUMN IF EXISTS filename;
ALTER TABLE backups DROP COLUMN IF EXISTS verified;
ALTER TABLE backups DROP COLUMN IF EXISTS metadata;

ALTER TABLE backup_schedules DROP COLUMN IF EXISTS type;
ALTER TABLE backup_schedules DROP COLUMN IF EXISTS retention_days;
ALTER TABLE backup_schedules DROP COLUMN IF EXISTS max_backups;
ALTER TABLE backup_schedules DROP COLUMN IF EXISTS last_run_status;
