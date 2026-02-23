CREATE TABLE ssl_targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    hostname        VARCHAR(512) NOT NULL,
    port            INTEGER NOT NULL DEFAULT 443,
    auto_discovered BOOLEAN NOT NULL DEFAULT false,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ssl_targets_host ON ssl_targets(host_id);

CREATE TABLE ssl_scan_results (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id           UUID NOT NULL REFERENCES ssl_targets(id) ON DELETE CASCADE,
    grade               VARCHAR(5) NOT NULL DEFAULT 'U',
    score               INTEGER NOT NULL DEFAULT 0,
    protocol_versions   TEXT[] DEFAULT '{}',
    cipher_suites       JSONB DEFAULT '[]',
    certificate_cn      VARCHAR(512) DEFAULT '',
    certificate_issuer  VARCHAR(512) DEFAULT '',
    certificate_sans    TEXT[] DEFAULT '{}',
    cert_not_before     TIMESTAMPTZ,
    cert_not_after      TIMESTAMPTZ,
    cert_key_type       VARCHAR(20) DEFAULT '',
    cert_key_bits       INTEGER DEFAULT 0,
    cert_chain_valid    BOOLEAN NOT NULL DEFAULT false,
    cert_chain_length   INTEGER DEFAULT 0,
    has_hsts            BOOLEAN NOT NULL DEFAULT false,
    has_ocsp_stapling   BOOLEAN NOT NULL DEFAULT false,
    has_sct             BOOLEAN NOT NULL DEFAULT false,
    vulnerabilities     JSONB DEFAULT '[]',
    error_message       TEXT DEFAULT '',
    scan_duration_ms    INTEGER DEFAULT 0,
    scanned_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ssl_scans_target ON ssl_scan_results(target_id);
CREATE INDEX idx_ssl_scans_grade ON ssl_scan_results(grade);
CREATE INDEX idx_ssl_scans_date ON ssl_scan_results(scanned_at DESC);
CREATE INDEX idx_ssl_scans_expiry ON ssl_scan_results(cert_not_after) WHERE cert_not_after IS NOT NULL;
