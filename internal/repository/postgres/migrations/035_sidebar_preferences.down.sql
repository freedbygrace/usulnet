-- ============================================================================
-- 035_sidebar_preferences (rollback)
-- ============================================================================

ALTER TABLE user_preferences
    DROP COLUMN IF EXISTS sidebar_prefs;
