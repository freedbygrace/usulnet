-- ============================================================================
-- 030_backup_drop_legacy_columns: Remove obsolete columns from backup tables
-- ============================================================================
-- The Go application uses target_name (not name) and type (not target_type).
-- These legacy columns cause NOT NULL constraint violations on INSERT because
-- the repository layer never populates them.

-- backups: drop 'name' (NOT NULL, never populated — target_name is used instead)
ALTER TABLE backups DROP COLUMN IF EXISTS name;

-- backups: drop 'target_type' (NOT NULL, never populated — type column is used)
ALTER TABLE backups DROP COLUMN IF EXISTS target_type;

-- backups: drop 'storage_path' (legacy column — path/filename are used instead)
ALTER TABLE backups DROP COLUMN IF EXISTS storage_path;

-- backups: drop 'storage_type' (not in Go model, not used)
ALTER TABLE backups DROP COLUMN IF EXISTS storage_type;

-- backup_schedules: drop 'name' (NOT NULL, never populated — target_name is used)
ALTER TABLE backup_schedules DROP COLUMN IF EXISTS name;

-- backup_schedules: drop 'target_type' (never populated — type column is used)
ALTER TABLE backup_schedules DROP COLUMN IF EXISTS target_type;

-- backup_schedules: drop 'storage_type' (not in Go model, not used)
ALTER TABLE backup_schedules DROP COLUMN IF EXISTS storage_type;

-- backup_schedules: drop 'retention_count' (legacy — retention_days is used instead)
ALTER TABLE backup_schedules DROP COLUMN IF EXISTS retention_count;
