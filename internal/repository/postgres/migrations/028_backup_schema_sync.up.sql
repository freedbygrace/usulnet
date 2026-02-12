-- ============================================================================
-- 028_backup_schema_sync: Add missing columns to backups and backup_schedules
-- ============================================================================

-- backups: add columns expected by the repository layer
ALTER TABLE backups ADD COLUMN IF NOT EXISTS trigger       VARCHAR(50) NOT NULL DEFAULT 'manual';
ALTER TABLE backups ADD COLUMN IF NOT EXISTS path          TEXT;
ALTER TABLE backups ADD COLUMN IF NOT EXISTS filename      VARCHAR(512);
ALTER TABLE backups ADD COLUMN IF NOT EXISTS verified      BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE backups ADD COLUMN IF NOT EXISTS metadata      JSONB;

-- backup_schedules: add columns expected by the repository layer
ALTER TABLE backup_schedules ADD COLUMN IF NOT EXISTS type            VARCHAR(50);
ALTER TABLE backup_schedules ADD COLUMN IF NOT EXISTS retention_days  INTEGER NOT NULL DEFAULT 30;
ALTER TABLE backup_schedules ADD COLUMN IF NOT EXISTS max_backups     INTEGER NOT NULL DEFAULT 10;
ALTER TABLE backup_schedules ADD COLUMN IF NOT EXISTS last_run_status VARCHAR(50);
