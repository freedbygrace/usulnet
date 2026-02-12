-- ============================================================================
-- 023_rdp_connections: RDP remote desktop connection profiles
-- ============================================================================

CREATE TABLE rdp_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,
    host            VARCHAR(255) NOT NULL,
    port            INTEGER NOT NULL DEFAULT 3389 CHECK (port > 0 AND port <= 65535),
    username        VARCHAR(255) NOT NULL DEFAULT '',
    domain          VARCHAR(255) NOT NULL DEFAULT '',
    password        TEXT NOT NULL DEFAULT '',
    resolution      VARCHAR(20) NOT NULL DEFAULT '1920x1080',
    color_depth     VARCHAR(5) NOT NULL DEFAULT '32',
    security        VARCHAR(10) NOT NULL DEFAULT 'any' CHECK (security IN ('any', 'nla', 'tls', 'rdp')),
    tags            JSONB NOT NULL DEFAULT '[]',
    status          VARCHAR(20) NOT NULL DEFAULT 'disconnected' CHECK (status IN ('active', 'disconnected', 'error')),
    status_message  TEXT NOT NULL DEFAULT '',
    last_checked    TIMESTAMPTZ,
    last_connected  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rdp_connections_user ON rdp_connections(user_id);
CREATE INDEX idx_rdp_connections_status ON rdp_connections(status);
CREATE UNIQUE INDEX idx_rdp_connections_unique_name ON rdp_connections(user_id, name);

CREATE TRIGGER update_rdp_connections_updated_at
    BEFORE UPDATE ON rdp_connections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE rdp_connections IS 'RDP remote desktop connection profiles';
