-- Rollback: remove password history and expiration
ALTER TABLE users DROP COLUMN IF EXISTS password_expires_at;
ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at;
DROP TABLE IF EXISTS password_history;
