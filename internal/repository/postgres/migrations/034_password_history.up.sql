-- 034_password_history: Password history and expiration support
-- Tracks previous password hashes to prevent reuse.
-- Adds password expiration fields to the users table.

CREATE TABLE IF NOT EXISTS password_history (
    id              BIGSERIAL PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash   VARCHAR(255) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_history_user ON password_history (user_id, created_at DESC);

-- Add password expiration tracking to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_expires_at TIMESTAMPTZ;

-- Set initial password_changed_at to created_at for existing users
UPDATE users SET password_changed_at = created_at WHERE password_changed_at IS NULL;
