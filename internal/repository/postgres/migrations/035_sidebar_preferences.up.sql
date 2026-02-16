-- ============================================================================
-- 035_sidebar_preferences: Add sidebar preferences JSONB column
-- ============================================================================
-- Stores per-user sidebar configuration: section collapse state and item
-- visibility. Schema:
-- {
--   "collapsed": {"tools": true, "integrations": true, "monitoring": true},
--   "hidden": {"swarm": true, "capture": true}
-- }

ALTER TABLE user_preferences
    ADD COLUMN IF NOT EXISTS sidebar_prefs JSONB NOT NULL DEFAULT '{}';
