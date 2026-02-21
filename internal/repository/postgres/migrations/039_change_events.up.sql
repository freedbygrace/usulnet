-- Migration 039: Structured Change Management Audit Trail
-- Phase 3: Immutable, searchable change events with before/after state snapshots

CREATE TABLE IF NOT EXISTS change_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    user_name       VARCHAR(255) NOT NULL DEFAULT '',
    client_ip       INET,
    resource_type   VARCHAR(100) NOT NULL,
    resource_id     VARCHAR(255) NOT NULL,
    resource_name   VARCHAR(512) NOT NULL DEFAULT '',
    action          VARCHAR(100) NOT NULL,
    old_state       JSONB,
    new_state       JSONB,
    diff_summary    TEXT NOT NULL DEFAULT '',
    related_ticket  VARCHAR(255) NOT NULL DEFAULT '',
    metadata        JSONB DEFAULT '{}',
    search_text     TSVECTOR
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_change_events_timestamp
    ON change_events (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_change_events_resource
    ON change_events (resource_type, resource_id);

CREATE INDEX IF NOT EXISTS idx_change_events_user
    ON change_events (user_id)
    WHERE user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_change_events_action
    ON change_events (action);

-- GIN index for full-text search over resource name, diff summary, action, ticket
CREATE INDEX IF NOT EXISTS idx_change_events_search
    ON change_events USING GIN (search_text);

-- Trigger to auto-populate search_text TSVECTOR on insert/update
CREATE OR REPLACE FUNCTION change_events_search_trigger() RETURNS trigger AS $$
BEGIN
    NEW.search_text :=
        setweight(to_tsvector('english', coalesce(NEW.resource_name, '')), 'A') ||
        setweight(to_tsvector('english', coalesce(NEW.resource_type, '')), 'B') ||
        setweight(to_tsvector('english', coalesce(NEW.action, '')), 'B') ||
        setweight(to_tsvector('english', coalesce(NEW.diff_summary, '')), 'C') ||
        setweight(to_tsvector('english', coalesce(NEW.related_ticket, '')), 'C') ||
        setweight(to_tsvector('english', coalesce(NEW.user_name, '')), 'D');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER change_events_search_update
    BEFORE INSERT OR UPDATE ON change_events
    FOR EACH ROW EXECUTE FUNCTION change_events_search_trigger();

-- Retention function matching the audit_log pattern
CREATE OR REPLACE FUNCTION cleanup_old_change_events(retention_days INTEGER DEFAULT 365)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM change_events
    WHERE timestamp < NOW() - (retention_days * INTERVAL '1 day');
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
