-- 046_dns: Internal DNS server management
-- Zones, records, TSIG keys, and audit logging for the embedded DNS server.

-- ============================================================================
-- DNS Zones
-- ============================================================================
CREATE TABLE dns_zones (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id       UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name          VARCHAR(255) NOT NULL,
    kind          VARCHAR(20) NOT NULL DEFAULT 'primary'
                  CHECK (kind IN ('primary', 'secondary', 'forward')),
    enabled       BOOLEAN NOT NULL DEFAULT true,
    ttl           INTEGER NOT NULL DEFAULT 3600,
    serial        BIGINT NOT NULL DEFAULT 1,
    refresh       INTEGER NOT NULL DEFAULT 3600,
    retry         INTEGER NOT NULL DEFAULT 900,
    expire        INTEGER NOT NULL DEFAULT 604800,
    minimum_ttl   INTEGER NOT NULL DEFAULT 300,
    primary_ns    VARCHAR(255) NOT NULL DEFAULT '',
    admin_email   VARCHAR(255) NOT NULL DEFAULT '',
    forwarders    TEXT[] NOT NULL DEFAULT '{}',
    description   TEXT DEFAULT '',
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(host_id, name)
);
CREATE INDEX idx_dns_zones_host ON dns_zones(host_id);
CREATE INDEX idx_dns_zones_enabled ON dns_zones(enabled);
CREATE TRIGGER update_dns_zones_updated_at
    BEFORE UPDATE ON dns_zones
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- DNS Records
-- ============================================================================
CREATE TABLE dns_records (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    zone_id    UUID NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    host_id    UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name       VARCHAR(255) NOT NULL,
    type       VARCHAR(10) NOT NULL
               CHECK (type IN ('A','AAAA','CNAME','MX','TXT','NS','SRV','PTR','CAA','SOA')),
    ttl        INTEGER NOT NULL DEFAULT 300,
    content    TEXT NOT NULL,
    priority   INTEGER,
    weight     INTEGER,
    port       INTEGER,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    comment    TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_dns_records_zone ON dns_records(zone_id);
CREATE INDEX idx_dns_records_host ON dns_records(host_id);
CREATE INDEX idx_dns_records_type ON dns_records(type);
CREATE TRIGGER update_dns_records_updated_at
    BEFORE UPDATE ON dns_records
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- DNS TSIG Keys (for zone transfers / dynamic updates)
-- ============================================================================
CREATE TABLE dns_tsig_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name        VARCHAR(255) NOT NULL,
    algorithm   VARCHAR(50) NOT NULL DEFAULT 'hmac-sha256',
    secret      TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_dns_tsig_host ON dns_tsig_keys(host_id);
CREATE TRIGGER update_dns_tsig_updated_at
    BEFORE UPDATE ON dns_tsig_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- DNS Audit Log
-- ============================================================================
CREATE TABLE dns_audit_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id       UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    action        VARCHAR(20) NOT NULL,
    resource_type VARCHAR(30) NOT NULL,
    resource_id   UUID NOT NULL,
    resource_name VARCHAR(255) DEFAULT '',
    details       TEXT DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_dns_audit_host ON dns_audit_log(host_id);
CREATE INDEX idx_dns_audit_created ON dns_audit_log(created_at DESC);
