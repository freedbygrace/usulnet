-- Session recording columns for terminal sessions
ALTER TABLE terminal_sessions
    ADD COLUMN IF NOT EXISTS recording_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS recording_path TEXT,
    ADD COLUMN IF NOT EXISTS recording_size BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS recording_format TEXT NOT NULL DEFAULT 'asciicast_v2';

-- Session recording configuration per user
CREATE TABLE IF NOT EXISTS session_recording_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_name TEXT,
    recording_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    retention_days INT NOT NULL DEFAULT 30,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_user_recording_config UNIQUE (user_id),
    CONSTRAINT unique_role_recording_config UNIQUE (role_name)
);

-- Index for looking up by user
CREATE INDEX IF NOT EXISTS idx_session_recording_configs_user ON session_recording_configs(user_id);

-- Index for finding sessions with recordings
CREATE INDEX IF NOT EXISTS idx_terminal_sessions_recording ON terminal_sessions(recording_enabled) WHERE recording_enabled = TRUE;

-- Cleanup function for expired recordings
CREATE OR REPLACE FUNCTION cleanup_expired_recordings(retention_default INT DEFAULT 30)
RETURNS INT AS $$
DECLARE
    deleted_count INT := 0;
BEGIN
    WITH expired AS (
        SELECT ts.id
        FROM terminal_sessions ts
        LEFT JOIN session_recording_configs src ON ts.user_id = src.user_id
        WHERE ts.recording_enabled = TRUE
          AND ts.recording_path IS NOT NULL
          AND ts.ended_at IS NOT NULL
          AND ts.ended_at < NOW() - MAKE_INTERVAL(days => COALESCE(src.retention_days, retention_default))
    )
    UPDATE terminal_sessions
    SET recording_path = NULL, recording_size = 0
    WHERE id IN (SELECT id FROM expired)
    RETURNING id INTO deleted_count;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
