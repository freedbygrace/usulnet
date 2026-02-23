CREATE TABLE wireguard_interfaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(50) NOT NULL DEFAULT 'wg0',
    display_name    VARCHAR(255) NOT NULL,
    description     TEXT DEFAULT '',
    listen_port     INTEGER NOT NULL DEFAULT 51820,
    address         VARCHAR(50) NOT NULL,              -- e.g. 10.0.0.1/24
    private_key     TEXT NOT NULL DEFAULT '',           -- encrypted
    public_key      TEXT NOT NULL DEFAULT '',
    dns             VARCHAR(255) DEFAULT '1.1.1.1',
    mtu             INTEGER DEFAULT 1420,
    post_up         TEXT DEFAULT '',
    post_down       TEXT DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    status          VARCHAR(20) NOT NULL DEFAULT 'inactive', -- inactive, active, error
    peer_count      INTEGER NOT NULL DEFAULT 0,
    last_handshake  TIMESTAMPTZ,
    transfer_rx     BIGINT DEFAULT 0,
    transfer_tx     BIGINT DEFAULT 0,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_wireguard_interfaces_host ON wireguard_interfaces(host_id);
CREATE INDEX idx_wireguard_interfaces_status ON wireguard_interfaces(status);
CREATE UNIQUE INDEX idx_wireguard_interfaces_host_name ON wireguard_interfaces(host_id, name);

CREATE TABLE wireguard_peers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    interface_id    UUID NOT NULL REFERENCES wireguard_interfaces(id) ON DELETE CASCADE,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT DEFAULT '',
    public_key      TEXT NOT NULL,
    preshared_key   TEXT DEFAULT '',
    allowed_ips     TEXT NOT NULL DEFAULT '10.0.0.0/24',  -- comma-separated CIDRs
    endpoint        VARCHAR(255) DEFAULT '',               -- client endpoint if known
    persistent_keepalive INTEGER DEFAULT 25,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_handshake  TIMESTAMPTZ,
    transfer_rx     BIGINT DEFAULT 0,
    transfer_tx     BIGINT DEFAULT 0,
    config_qr       TEXT DEFAULT '',                       -- base64 QR code PNG
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_wireguard_peers_interface ON wireguard_peers(interface_id);
CREATE INDEX idx_wireguard_peers_host ON wireguard_peers(host_id);
CREATE INDEX idx_wireguard_peers_enabled ON wireguard_peers(enabled);
