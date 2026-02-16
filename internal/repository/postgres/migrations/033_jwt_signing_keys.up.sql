-- 033_jwt_signing_keys: JWT signing key rotation support
-- Stores multiple JWT signing keys for key rotation.
-- The most recently created active key is used for signing new tokens.
-- Previous keys remain active for validation until they expire.

CREATE TABLE IF NOT EXISTS jwt_signing_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash        VARCHAR(64) NOT NULL,           -- SHA-256 hash of the key (for identification, not the key itself)
    encrypted_key   BYTEA NOT NULL,                 -- AES-256-GCM encrypted signing key
    algorithm       VARCHAR(16) NOT NULL DEFAULT 'HS256',
    status          VARCHAR(16) NOT NULL DEFAULT 'active',  -- active, retired, revoked
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at    TIMESTAMPTZ,                    -- when key became the primary signing key
    expires_at      TIMESTAMPTZ,                    -- when key should stop validating tokens
    revoked_at      TIMESTAMPTZ,                    -- when key was explicitly revoked
    revoked_by      UUID REFERENCES users(id),
    created_by      UUID REFERENCES users(id),
    metadata        JSONB DEFAULT '{}',             -- additional metadata (rotation reason, etc.)
    CONSTRAINT chk_jwt_key_status CHECK (status IN ('active', 'retired', 'revoked'))
);

CREATE INDEX idx_jwt_signing_keys_status ON jwt_signing_keys (status);
CREATE INDEX idx_jwt_signing_keys_created ON jwt_signing_keys (created_at DESC);
