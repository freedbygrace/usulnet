-- ============================================================================
-- 025_persistent_features: Add DB persistence for in-memory features
-- ============================================================================

-- ============================================================================
-- 1. Compliance Policies
-- ============================================================================
CREATE TABLE IF NOT EXISTS compliance_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    category        VARCHAR(50) NOT NULL DEFAULT 'security',
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium',
    rule            VARCHAR(100) NOT NULL,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    is_enforced     BOOLEAN NOT NULL DEFAULT false,
    last_check_at   TIMESTAMPTZ,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_policies_enabled ON compliance_policies(is_enabled);
CREATE INDEX idx_compliance_policies_category ON compliance_policies(category);

CREATE TRIGGER update_compliance_policies_updated_at
    BEFORE UPDATE ON compliance_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE IF NOT EXISTS compliance_violations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES compliance_policies(id) ON DELETE CASCADE,
    policy_name     VARCHAR(255) NOT NULL,
    container_id    VARCHAR(128) NOT NULL,
    container_name  VARCHAR(255) NOT NULL DEFAULT '',
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium',
    message         TEXT NOT NULL DEFAULT '',
    details         TEXT NOT NULL DEFAULT '',
    status          VARCHAR(20) NOT NULL DEFAULT 'open',
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    resolved_by     UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_compliance_violations_policy ON compliance_violations(policy_id);
CREATE INDEX idx_compliance_violations_status ON compliance_violations(status);
CREATE INDEX idx_compliance_violations_container ON compliance_violations(container_id);

-- ============================================================================
-- 2. Managed Secrets
-- ============================================================================
CREATE TABLE IF NOT EXISTS managed_secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    type            VARCHAR(50) NOT NULL DEFAULT 'generic',
    scope           VARCHAR(50) NOT NULL DEFAULT 'global',
    scope_target    VARCHAR(255) NOT NULL DEFAULT '',
    encrypted_value TEXT NOT NULL DEFAULT '',
    rotation_days   INTEGER NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ,
    linked_count    INTEGER NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_managed_secrets_scope ON managed_secrets(scope, scope_target);
CREATE INDEX idx_managed_secrets_type ON managed_secrets(type);
CREATE INDEX idx_managed_secrets_expires ON managed_secrets(expires_at) WHERE expires_at IS NOT NULL;

CREATE TRIGGER update_managed_secrets_updated_at
    BEFORE UPDATE ON managed_secrets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 3. Lifecycle Policies
-- ============================================================================
CREATE TABLE IF NOT EXISTS lifecycle_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    resource_type   VARCHAR(50) NOT NULL,
    action          VARCHAR(50) NOT NULL,
    schedule        VARCHAR(100) NOT NULL DEFAULT '',
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    only_dangling   BOOLEAN NOT NULL DEFAULT false,
    only_stopped    BOOLEAN NOT NULL DEFAULT false,
    only_unused     BOOLEAN NOT NULL DEFAULT false,
    max_age_days    INTEGER NOT NULL DEFAULT 0,
    keep_latest     INTEGER NOT NULL DEFAULT 0,
    exclude_labels  TEXT NOT NULL DEFAULT '',
    include_labels  TEXT NOT NULL DEFAULT '',
    last_executed_at TIMESTAMPTZ,
    last_result     VARCHAR(50) NOT NULL DEFAULT '',
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_lifecycle_policies_enabled ON lifecycle_policies(is_enabled);
CREATE INDEX idx_lifecycle_policies_type ON lifecycle_policies(resource_type);

CREATE TRIGGER update_lifecycle_policies_updated_at
    BEFORE UPDATE ON lifecycle_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE IF NOT EXISTS lifecycle_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID REFERENCES lifecycle_policies(id) ON DELETE SET NULL,
    policy_name     VARCHAR(255) NOT NULL,
    resource_type   VARCHAR(50) NOT NULL,
    action          VARCHAR(50) NOT NULL,
    items_removed   BIGINT NOT NULL DEFAULT 0,
    space_freed     BIGINT NOT NULL DEFAULT 0,
    status          VARCHAR(20) NOT NULL DEFAULT 'success',
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT NOT NULL DEFAULT '',
    executed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_lifecycle_history_policy ON lifecycle_history(policy_id);
CREATE INDEX idx_lifecycle_history_executed ON lifecycle_history(executed_at DESC);

-- ============================================================================
-- 4. Maintenance Windows
-- ============================================================================
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    host_id         VARCHAR(255) NOT NULL DEFAULT '',
    host_name       VARCHAR(255) NOT NULL DEFAULT 'All Hosts',
    schedule        VARCHAR(100) NOT NULL,
    duration_minutes INTEGER NOT NULL DEFAULT 60,
    actions         JSONB NOT NULL DEFAULT '{}',
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    is_active       BOOLEAN NOT NULL DEFAULT false,
    last_run_at     TIMESTAMPTZ,
    last_status     VARCHAR(20) NOT NULL DEFAULT '',
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_maintenance_windows_enabled ON maintenance_windows(is_enabled);
CREATE INDEX idx_maintenance_windows_host ON maintenance_windows(host_id);

CREATE TRIGGER update_maintenance_windows_updated_at
    BEFORE UPDATE ON maintenance_windows
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 5. GitOps Pipelines
-- ============================================================================
CREATE TABLE IF NOT EXISTS gitops_pipelines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    repository      VARCHAR(512) NOT NULL,
    branch          VARCHAR(255) NOT NULL DEFAULT 'main',
    provider        VARCHAR(50) NOT NULL DEFAULT 'github',
    target_stack    VARCHAR(255) NOT NULL DEFAULT '',
    target_service  VARCHAR(255) NOT NULL DEFAULT '',
    action          VARCHAR(50) NOT NULL DEFAULT 'redeploy',
    trigger_type    VARCHAR(50) NOT NULL DEFAULT 'manual',
    schedule        VARCHAR(100) NOT NULL DEFAULT '',
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    auto_rollback   BOOLEAN NOT NULL DEFAULT true,
    deploy_count    INTEGER NOT NULL DEFAULT 0,
    last_deploy_at  TIMESTAMPTZ,
    last_status     VARCHAR(20) NOT NULL DEFAULT '',
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_gitops_pipelines_enabled ON gitops_pipelines(is_enabled);
CREATE INDEX idx_gitops_pipelines_repo ON gitops_pipelines(repository);

CREATE TRIGGER update_gitops_pipelines_updated_at
    BEFORE UPDATE ON gitops_pipelines
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE IF NOT EXISTS gitops_deployments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipeline_id     UUID REFERENCES gitops_pipelines(id) ON DELETE SET NULL,
    pipeline_name   VARCHAR(255) NOT NULL,
    repository      VARCHAR(512) NOT NULL,
    branch          VARCHAR(255) NOT NULL DEFAULT '',
    commit_sha      VARCHAR(64) NOT NULL DEFAULT '',
    commit_msg      TEXT NOT NULL DEFAULT '',
    action          VARCHAR(50) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    error_message   TEXT NOT NULL DEFAULT '',
    triggered_by    VARCHAR(50) NOT NULL DEFAULT 'manual'
);

CREATE INDEX idx_gitops_deployments_pipeline ON gitops_deployments(pipeline_id);
CREATE INDEX idx_gitops_deployments_status ON gitops_deployments(status);
CREATE INDEX idx_gitops_deployments_started ON gitops_deployments(started_at DESC);

-- ============================================================================
-- 6. Resource Quotas
-- ============================================================================
CREATE TABLE IF NOT EXISTS resource_quotas (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    scope           VARCHAR(255) NOT NULL DEFAULT 'global',
    scope_name      VARCHAR(255) NOT NULL DEFAULT 'Global',
    resource_type   VARCHAR(50) NOT NULL,
    limit_value     BIGINT NOT NULL,
    alert_at        INTEGER NOT NULL DEFAULT 80,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_resource_quotas_scope ON resource_quotas(scope);
CREATE INDEX idx_resource_quotas_enabled ON resource_quotas(is_enabled);

CREATE TRIGGER update_resource_quotas_updated_at
    BEFORE UPDATE ON resource_quotas
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 7. Container Templates
-- ============================================================================
CREATE TABLE IF NOT EXISTS container_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    category        VARCHAR(100) NOT NULL DEFAULT 'general',
    image           VARCHAR(512) NOT NULL,
    tag             VARCHAR(128) NOT NULL DEFAULT 'latest',
    ports           TEXT[] NOT NULL DEFAULT '{}',
    volumes         TEXT[] NOT NULL DEFAULT '{}',
    env_vars        JSONB NOT NULL DEFAULT '[]',
    network         VARCHAR(255) NOT NULL DEFAULT '',
    restart_policy  VARCHAR(50) NOT NULL DEFAULT 'unless-stopped',
    command         TEXT NOT NULL DEFAULT '',
    is_public       BOOLEAN NOT NULL DEFAULT false,
    usage_count     INTEGER NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_container_templates_category ON container_templates(category);
CREATE INDEX idx_container_templates_public ON container_templates(is_public);

CREATE TRIGGER update_container_templates_updated_at
    BEFORE UPDATE ON container_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 8. Tracked Vulnerabilities
-- ============================================================================
CREATE TABLE IF NOT EXISTS tracked_vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id          VARCHAR(50) NOT NULL,
    title           VARCHAR(512) NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium',
    cvss_score      VARCHAR(10) NOT NULL DEFAULT '',
    package         VARCHAR(255) NOT NULL DEFAULT '',
    installed_ver   VARCHAR(100) NOT NULL DEFAULT '',
    fixed_ver       VARCHAR(100) NOT NULL DEFAULT '',
    affected_images TEXT[] NOT NULL DEFAULT '{}',
    container_count INTEGER NOT NULL DEFAULT 0,
    status          VARCHAR(20) NOT NULL DEFAULT 'open',
    priority        VARCHAR(10) NOT NULL DEFAULT 'p2',
    sla_deadline    TIMESTAMPTZ,
    assignee        VARCHAR(255) NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT '',
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_tracked_vulnerabilities_cve ON tracked_vulnerabilities(cve_id);
CREATE INDEX idx_tracked_vulnerabilities_status ON tracked_vulnerabilities(status);
CREATE INDEX idx_tracked_vulnerabilities_severity ON tracked_vulnerabilities(severity);
CREATE INDEX idx_tracked_vulnerabilities_priority ON tracked_vulnerabilities(priority);

CREATE TRIGGER update_tracked_vulnerabilities_updated_at
    BEFORE UPDATE ON tracked_vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
