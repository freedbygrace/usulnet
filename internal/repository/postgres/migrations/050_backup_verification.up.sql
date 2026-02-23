-- ============================================================================
-- 050_backup_verification: Automated backup verification
-- ============================================================================

CREATE TABLE backup_verifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_id       UUID NOT NULL REFERENCES backups(id) ON DELETE CASCADE,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    method          VARCHAR(30) NOT NULL DEFAULT 'extract',
    checksum_valid  BOOLEAN,
    files_readable  BOOLEAN,
    container_test  BOOLEAN,
    data_valid      BOOLEAN,
    file_count      INTEGER DEFAULT 0,
    size_bytes      BIGINT DEFAULT 0,
    duration_ms     INTEGER DEFAULT 0,
    error_message   TEXT DEFAULT '',
    details         JSONB DEFAULT '{}',
    verified_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_backup_verifications_backup ON backup_verifications(backup_id);
CREATE INDEX idx_backup_verifications_host ON backup_verifications(host_id);
CREATE INDEX idx_backup_verifications_status ON backup_verifications(status);

CREATE TABLE backup_verification_schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    schedule        VARCHAR(100) NOT NULL DEFAULT '0 3 * * 0',
    method          VARCHAR(30) NOT NULL DEFAULT 'extract',
    max_backups     INTEGER NOT NULL DEFAULT 5,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_run_at     TIMESTAMPTZ,
    last_run_status VARCHAR(20),
    next_run_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bv_schedules_host ON backup_verification_schedules(host_id);
