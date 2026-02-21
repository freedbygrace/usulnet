DROP FUNCTION IF EXISTS cleanup_expired_recordings;
DROP INDEX IF EXISTS idx_terminal_sessions_recording;
DROP INDEX IF EXISTS idx_session_recording_configs_user;
DROP TABLE IF EXISTS session_recording_configs;
ALTER TABLE terminal_sessions
    DROP COLUMN IF EXISTS recording_format,
    DROP COLUMN IF EXISTS recording_size,
    DROP COLUMN IF EXISTS recording_path,
    DROP COLUMN IF EXISTS recording_enabled;
