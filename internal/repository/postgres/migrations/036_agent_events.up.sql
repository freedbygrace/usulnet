-- Agent event persistence for gateway events received from remote agents.
CREATE TABLE IF NOT EXISTS agent_events (
    id          VARCHAR(64) PRIMARY KEY,
    event_type  VARCHAR(128) NOT NULL,
    agent_id    VARCHAR(128) NOT NULL,
    host_id     UUID,
    severity    VARCHAR(16) NOT NULL DEFAULT 'info',
    message     TEXT NOT NULL DEFAULT '',
    actor_json  JSONB,
    attributes  JSONB,
    data        JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_events_host ON agent_events(host_id);
CREATE INDEX IF NOT EXISTS idx_agent_events_agent ON agent_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_events_type ON agent_events(event_type);
CREATE INDEX IF NOT EXISTS idx_agent_events_created ON agent_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_events_severity ON agent_events(severity);
