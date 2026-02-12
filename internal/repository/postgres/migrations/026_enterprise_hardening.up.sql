-- Migration 026: Enterprise Hardening (Phase 2)
-- Adds tables for: dashboard widgets, log aggregation, compliance frameworks,
-- image signing, runtime security events, and OPA policies.

-- ============================================================================
-- 1. Dashboard Widgets & Layouts
-- ============================================================================

CREATE TABLE IF NOT EXISTS dashboard_layouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    is_default BOOLEAN NOT NULL DEFAULT false,
    is_shared BOOLEAN NOT NULL DEFAULT false,
    layout_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dashboard_widgets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    layout_id UUID NOT NULL REFERENCES dashboard_layouts(id) ON DELETE CASCADE,
    widget_type VARCHAR(64) NOT NULL, -- 'cpu_gauge', 'memory_chart', 'container_table', 'log_stream', 'alert_feed', etc.
    title VARCHAR(255) NOT NULL DEFAULT '',
    config JSONB NOT NULL DEFAULT '{}'::jsonb, -- widget-specific config (data source, thresholds, etc.)
    position_x INT NOT NULL DEFAULT 0,
    position_y INT NOT NULL DEFAULT 0,
    width INT NOT NULL DEFAULT 6,
    height INT NOT NULL DEFAULT 4,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dashboard_layouts_user ON dashboard_layouts(user_id);
CREATE INDEX IF NOT EXISTS idx_dashboard_widgets_layout ON dashboard_widgets(layout_id);

-- ============================================================================
-- 2. Log Aggregation & Search
-- ============================================================================

CREATE TABLE IF NOT EXISTS aggregated_logs (
    id BIGSERIAL PRIMARY KEY,
    host_id UUID,
    container_id VARCHAR(128),
    container_name VARCHAR(255),
    source VARCHAR(64) NOT NULL DEFAULT 'docker', -- 'docker', 'system', 'application', 'audit'
    stream VARCHAR(16) NOT NULL DEFAULT 'stdout', -- 'stdout', 'stderr'
    severity VARCHAR(16) NOT NULL DEFAULT 'info', -- 'debug', 'info', 'warn', 'error', 'fatal'
    message TEXT NOT NULL,
    fields JSONB, -- structured fields extracted from log line
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aggregated_logs_container ON aggregated_logs(container_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_aggregated_logs_severity ON aggregated_logs(severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_aggregated_logs_source ON aggregated_logs(source, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_aggregated_logs_host ON aggregated_logs(host_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_aggregated_logs_timestamp_brin ON aggregated_logs USING BRIN(timestamp);
CREATE INDEX IF NOT EXISTS idx_aggregated_logs_message_gin ON aggregated_logs USING GIN(to_tsvector('english', message));

-- Log search saved queries
CREATE TABLE IF NOT EXISTS log_search_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    query TEXT NOT NULL,
    filters JSONB NOT NULL DEFAULT '{}'::jsonb,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    is_shared BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- 3. Compliance Frameworks (SOC2, HIPAA, PCI-DSS)
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL UNIQUE, -- 'soc2', 'hipaa', 'pci-dss', 'custom'
    display_name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    version VARCHAR(32) NOT NULL DEFAULT '1.0',
    is_enabled BOOLEAN NOT NULL DEFAULT false,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_id VARCHAR(64) NOT NULL, -- e.g., 'CC6.1', 'A.164.312(a)(1)', '1.1.1'
    title VARCHAR(512) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category VARCHAR(128) NOT NULL DEFAULT '', -- e.g., 'Access Control', 'Encryption', 'Audit Logging'
    severity VARCHAR(16) NOT NULL DEFAULT 'medium',
    implementation_status VARCHAR(32) NOT NULL DEFAULT 'not_started', -- 'not_started', 'in_progress', 'implemented', 'not_applicable'
    evidence_type VARCHAR(64) NOT NULL DEFAULT 'automated', -- 'automated', 'manual', 'hybrid'
    check_query TEXT, -- SQL or OPA query for automated checks
    remediation TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(framework_id, control_id)
);

CREATE TABLE IF NOT EXISTS compliance_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'in_progress', -- 'in_progress', 'completed', 'failed'
    total_controls INT NOT NULL DEFAULT 0,
    passed_controls INT NOT NULL DEFAULT 0,
    failed_controls INT NOT NULL DEFAULT 0,
    na_controls INT NOT NULL DEFAULT 0,
    score FLOAT NOT NULL DEFAULT 0,
    results JSONB NOT NULL DEFAULT '[]'::jsonb, -- per-control results
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL REFERENCES compliance_assessments(id) ON DELETE CASCADE,
    control_id UUID NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
    evidence_type VARCHAR(64) NOT NULL, -- 'screenshot', 'log_export', 'config_snapshot', 'scan_result', 'automated_check'
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    data JSONB, -- structured evidence data
    file_path VARCHAR(1024), -- path for file-based evidence
    status VARCHAR(32) NOT NULL DEFAULT 'valid', -- 'valid', 'expired', 'invalid'
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_controls_framework ON compliance_controls(framework_id);
CREATE INDEX IF NOT EXISTS idx_compliance_assessments_framework ON compliance_assessments(framework_id);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_assessment ON compliance_evidence(assessment_id);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_control ON compliance_evidence(control_id);

-- ============================================================================
-- 4. OPA Policy Engine
-- ============================================================================

CREATE TABLE IF NOT EXISTS opa_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    category VARCHAR(64) NOT NULL DEFAULT 'general', -- 'admission', 'runtime', 'network', 'image', 'general'
    rego_code TEXT NOT NULL, -- OPA Rego policy code
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    is_enforcing BOOLEAN NOT NULL DEFAULT false, -- false = audit-only, true = enforce/block
    severity VARCHAR(16) NOT NULL DEFAULT 'medium',
    last_evaluated_at TIMESTAMPTZ,
    evaluation_count BIGINT NOT NULL DEFAULT 0,
    violation_count BIGINT NOT NULL DEFAULT 0,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS opa_evaluation_results (
    id BIGSERIAL PRIMARY KEY,
    policy_id UUID NOT NULL REFERENCES opa_policies(id) ON DELETE CASCADE,
    target_type VARCHAR(64) NOT NULL, -- 'container', 'image', 'network', 'volume'
    target_id VARCHAR(255) NOT NULL,
    target_name VARCHAR(255) NOT NULL DEFAULT '',
    decision BOOLEAN NOT NULL, -- true = allowed, false = denied
    violations JSONB, -- list of specific violations
    input_hash VARCHAR(64), -- SHA-256 of input data for deduplication
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_opa_policies_category ON opa_policies(category) WHERE is_enabled = true;
CREATE INDEX IF NOT EXISTS idx_opa_results_policy ON opa_evaluation_results(policy_id, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_opa_results_target ON opa_evaluation_results(target_type, target_id, evaluated_at DESC);

-- ============================================================================
-- 5. Image Signing & Verification (Sigstore/cosign)
-- ============================================================================

CREATE TABLE IF NOT EXISTS image_signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_ref VARCHAR(512) NOT NULL, -- full image reference (registry/repo:tag)
    image_digest VARCHAR(128) NOT NULL, -- sha256:...
    signature_type VARCHAR(32) NOT NULL DEFAULT 'cosign', -- 'cosign', 'notary', 'gpg'
    signature_data TEXT, -- base64-encoded signature
    certificate TEXT, -- signing certificate (PEM)
    signer_identity VARCHAR(255), -- email or OIDC identity
    issuer VARCHAR(255), -- OIDC issuer URL
    transparency_log_id VARCHAR(255), -- Rekor transparency log entry
    verified BOOLEAN NOT NULL DEFAULT false,
    verified_at TIMESTAMPTZ,
    verification_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS image_attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_ref VARCHAR(512) NOT NULL,
    image_digest VARCHAR(128) NOT NULL,
    predicate_type VARCHAR(255) NOT NULL, -- 'https://slsa.dev/provenance/v0.2', 'https://spdx.dev/Document', etc.
    predicate JSONB NOT NULL, -- attestation predicate data
    signer_identity VARCHAR(255),
    verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS image_trust_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    image_pattern VARCHAR(512) NOT NULL, -- glob pattern for matching images (e.g., 'registry.example.com/*')
    require_signature BOOLEAN NOT NULL DEFAULT false,
    require_attestation BOOLEAN NOT NULL DEFAULT false,
    allowed_signers JSONB NOT NULL DEFAULT '[]'::jsonb, -- list of allowed signer identities
    allowed_issuers JSONB NOT NULL DEFAULT '[]'::jsonb, -- list of allowed OIDC issuers
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    is_enforcing BOOLEAN NOT NULL DEFAULT false, -- false = warn, true = block
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_image_signatures_ref ON image_signatures(image_ref);
CREATE INDEX IF NOT EXISTS idx_image_signatures_digest ON image_signatures(image_digest);
CREATE INDEX IF NOT EXISTS idx_image_attestations_digest ON image_attestations(image_digest);
CREATE INDEX IF NOT EXISTS idx_image_trust_policies_enabled ON image_trust_policies(is_enabled) WHERE is_enabled = true;

-- ============================================================================
-- 6. Runtime Threat Detection
-- ============================================================================

CREATE TABLE IF NOT EXISTS runtime_security_events (
    id BIGSERIAL PRIMARY KEY,
    host_id UUID,
    container_id VARCHAR(128) NOT NULL,
    container_name VARCHAR(255) NOT NULL DEFAULT '',
    event_type VARCHAR(64) NOT NULL, -- 'process_exec', 'file_access', 'network_connect', 'privilege_escalation', 'anomaly'
    severity VARCHAR(16) NOT NULL DEFAULT 'info',
    rule_id VARCHAR(128), -- which detection rule triggered
    rule_name VARCHAR(255),
    description TEXT NOT NULL DEFAULT '',
    details JSONB, -- event-specific details (process info, file path, network dest, etc.)
    source VARCHAR(64) NOT NULL DEFAULT 'usulnet', -- 'usulnet', 'falco', 'seccomp', 'apparmor'
    action_taken VARCHAR(32) NOT NULL DEFAULT 'alert', -- 'alert', 'block', 'kill', 'quarantine'
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMPTZ,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS runtime_security_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    category VARCHAR(64) NOT NULL DEFAULT 'general', -- 'process', 'file', 'network', 'privilege', 'anomaly'
    rule_type VARCHAR(32) NOT NULL DEFAULT 'pattern', -- 'pattern', 'behavioral', 'threshold'
    definition JSONB NOT NULL, -- rule-specific config
    severity VARCHAR(16) NOT NULL DEFAULT 'medium',
    action VARCHAR(32) NOT NULL DEFAULT 'alert', -- 'alert', 'block', 'kill'
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    container_filter VARCHAR(512), -- optional container name/label filter
    event_count BIGINT NOT NULL DEFAULT 0,
    last_triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS runtime_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    container_id VARCHAR(128) NOT NULL,
    container_name VARCHAR(255) NOT NULL DEFAULT '',
    image VARCHAR(512) NOT NULL DEFAULT '',
    baseline_type VARCHAR(32) NOT NULL, -- 'process', 'network', 'filesystem'
    baseline_data JSONB NOT NULL, -- learned normal behavior
    sample_count INT NOT NULL DEFAULT 0,
    confidence FLOAT NOT NULL DEFAULT 0, -- 0-1 confidence level
    is_active BOOLEAN NOT NULL DEFAULT false,
    learning_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    learning_completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_runtime_events_container ON runtime_security_events(container_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_runtime_events_severity ON runtime_security_events(severity, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_runtime_events_type ON runtime_security_events(event_type, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_runtime_events_timestamp_brin ON runtime_security_events USING BRIN(detected_at);
CREATE INDEX IF NOT EXISTS idx_runtime_baselines_container ON runtime_baselines(container_id) WHERE is_active = true;
