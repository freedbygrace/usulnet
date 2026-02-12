-- Migration 027: GitOps Market Expansion (Phase 3)
-- Adds tables for: bidirectional git sync, ephemeral environments, manifest builder.

-- ============================================================================
-- A) Bidirectional Git Sync
-- ============================================================================

-- 1. git_sync_configs - Configuration for bidirectional sync between UI and Git
CREATE TABLE IF NOT EXISTS git_sync_configs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id           UUID NOT NULL REFERENCES gitea_connections(id) ON DELETE CASCADE,
    repository_id           UUID NOT NULL REFERENCES gitea_repositories(id) ON DELETE CASCADE,
    name                    VARCHAR(255) NOT NULL,
    sync_direction          VARCHAR(20) NOT NULL DEFAULT 'bidirectional', -- 'to_git', 'from_git', 'bidirectional'
    target_path             VARCHAR(512) NOT NULL DEFAULT '/',            -- path in repo to sync
    stack_name              VARCHAR(255) NOT NULL DEFAULT '',             -- associated Docker stack
    file_pattern            VARCHAR(255) NOT NULL DEFAULT '*.yml',       -- file patterns to watch
    branch                  VARCHAR(255) NOT NULL DEFAULT 'main',
    auto_commit             BOOLEAN NOT NULL DEFAULT true,
    auto_deploy             BOOLEAN NOT NULL DEFAULT false,
    commit_message_template VARCHAR(512) NOT NULL DEFAULT 'chore: sync {{.Resource}} via usulnet',
    conflict_strategy       VARCHAR(20) NOT NULL DEFAULT 'manual',       -- 'manual', 'prefer_git', 'prefer_ui'
    is_enabled              BOOLEAN NOT NULL DEFAULT true,
    last_sync_at            TIMESTAMPTZ,
    last_sync_status        VARCHAR(20) NOT NULL DEFAULT '',
    last_sync_error         TEXT NOT NULL DEFAULT '',
    sync_count              INTEGER NOT NULL DEFAULT 0,
    created_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_git_sync_configs_connection ON git_sync_configs(connection_id);
CREATE INDEX idx_git_sync_configs_repository ON git_sync_configs(repository_id);
CREATE INDEX idx_git_sync_configs_enabled ON git_sync_configs(is_enabled);
CREATE INDEX idx_git_sync_configs_stack ON git_sync_configs(stack_name);

CREATE TRIGGER update_git_sync_configs_updated_at
    BEFORE UPDATE ON git_sync_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 2. git_sync_events - Log of sync operations
CREATE TABLE IF NOT EXISTS git_sync_events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id         UUID NOT NULL REFERENCES git_sync_configs(id) ON DELETE CASCADE,
    direction         VARCHAR(20) NOT NULL,            -- 'to_git', 'from_git'
    event_type        VARCHAR(50) NOT NULL,            -- 'commit_pushed', 'file_updated', 'conflict_detected', 'deploy_triggered'
    status            VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'success', 'failed', 'conflict'
    commit_sha        VARCHAR(64) NOT NULL DEFAULT '',
    commit_message    TEXT NOT NULL DEFAULT '',
    files_changed     JSONB NOT NULL DEFAULT '[]'::jsonb,    -- list of changed file paths
    diff_summary      TEXT NOT NULL DEFAULT '',               -- short summary of changes
    error_message     TEXT NOT NULL DEFAULT '',
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_git_sync_events_config ON git_sync_events(config_id);
CREATE INDEX idx_git_sync_events_status ON git_sync_events(status);
CREATE INDEX idx_git_sync_events_created ON git_sync_events(created_at DESC);

-- 3. git_sync_conflicts - Conflicts detected during bidirectional sync
CREATE TABLE IF NOT EXISTS git_sync_conflicts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id       UUID NOT NULL REFERENCES git_sync_configs(id) ON DELETE CASCADE,
    event_id        UUID REFERENCES git_sync_events(id) ON DELETE SET NULL,
    file_path       VARCHAR(512) NOT NULL,
    git_content     TEXT NOT NULL DEFAULT '',
    ui_content      TEXT NOT NULL DEFAULT '',
    base_content    TEXT NOT NULL DEFAULT '',
    resolution      VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'use_git', 'use_ui', 'merged', 'dismissed'
    resolved_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at     TIMESTAMPTZ,
    merged_content  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_git_sync_conflicts_config ON git_sync_conflicts(config_id);
CREATE INDEX idx_git_sync_conflicts_resolution ON git_sync_conflicts(resolution);

-- ============================================================================
-- B) Branch-based Ephemeral Environments
-- ============================================================================

-- 4. ephemeral_environments - Temporary environments spun up from branches
CREATE TABLE IF NOT EXISTS ephemeral_environments (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              VARCHAR(255) NOT NULL,
    connection_id     UUID REFERENCES gitea_connections(id) ON DELETE SET NULL,
    repository_id     UUID REFERENCES gitea_repositories(id) ON DELETE SET NULL,
    branch            VARCHAR(255) NOT NULL,
    commit_sha        VARCHAR(64) NOT NULL DEFAULT '',
    stack_name        VARCHAR(255) NOT NULL,              -- the Docker stack created for this env
    compose_file      TEXT NOT NULL DEFAULT '',            -- the resolved compose content
    environment       JSONB NOT NULL DEFAULT '{}'::jsonb,  -- env vars applied
    port_mappings     JSONB NOT NULL DEFAULT '{}'::jsonb,  -- port offset mapping
    status            VARCHAR(30) NOT NULL DEFAULT 'pending', -- 'pending', 'provisioning', 'running', 'stopping', 'stopped', 'failed', 'expired'
    url               VARCHAR(512) NOT NULL DEFAULT '',    -- access URL for the environment
    ttl_minutes       INTEGER NOT NULL DEFAULT 1440,       -- 24h default TTL
    auto_destroy      BOOLEAN NOT NULL DEFAULT true,
    expires_at        TIMESTAMPTZ,
    started_at        TIMESTAMPTZ,
    stopped_at        TIMESTAMPTZ,
    error_message     TEXT NOT NULL DEFAULT '',
    resource_limits   JSONB NOT NULL DEFAULT '{}'::jsonb,  -- cpu, memory limits
    labels            JSONB NOT NULL DEFAULT '{}'::jsonb,  -- custom labels
    created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ephemeral_environments_status ON ephemeral_environments(status);
CREATE INDEX idx_ephemeral_environments_branch ON ephemeral_environments(branch);
CREATE INDEX idx_ephemeral_environments_repository ON ephemeral_environments(repository_id);
CREATE INDEX idx_ephemeral_environments_expires ON ephemeral_environments(expires_at);
CREATE INDEX idx_ephemeral_environments_stack ON ephemeral_environments(stack_name);

CREATE TRIGGER update_ephemeral_environments_updated_at
    BEFORE UPDATE ON ephemeral_environments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 5. ephemeral_environment_logs - Logs from ephemeral env lifecycle
CREATE TABLE IF NOT EXISTS ephemeral_environment_logs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id    UUID NOT NULL REFERENCES ephemeral_environments(id) ON DELETE CASCADE,
    phase             VARCHAR(30) NOT NULL,               -- 'provision', 'deploy', 'healthcheck', 'destroy'
    message           TEXT NOT NULL DEFAULT '',
    level             VARCHAR(10) NOT NULL DEFAULT 'info', -- 'info', 'warn', 'error'
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ephemeral_env_logs_env ON ephemeral_environment_logs(environment_id);
CREATE INDEX idx_ephemeral_env_logs_created ON ephemeral_environment_logs(created_at DESC);

-- ============================================================================
-- C) Visual GitOps Manifest Builder
-- ============================================================================

-- 6. manifest_templates - Saved manifest templates/blueprints
CREATE TABLE IF NOT EXISTS manifest_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    format          VARCHAR(30) NOT NULL DEFAULT 'compose',   -- 'compose', 'kubernetes', 'swarm'
    category        VARCHAR(100) NOT NULL DEFAULT 'custom',   -- 'web', 'database', 'monitoring', 'custom', etc.
    icon            VARCHAR(100) NOT NULL DEFAULT '',
    version         VARCHAR(50) NOT NULL DEFAULT '1.0.0',
    content         TEXT NOT NULL,                            -- the YAML/JSON manifest content
    variables       JSONB NOT NULL DEFAULT '[]'::jsonb,       -- template variables [{name, type, default, description, required}]
    is_public       BOOLEAN NOT NULL DEFAULT false,
    is_builtin      BOOLEAN NOT NULL DEFAULT false,
    usage_count     INTEGER NOT NULL DEFAULT 0,
    tags            JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_manifest_templates_format ON manifest_templates(format);
CREATE INDEX idx_manifest_templates_category ON manifest_templates(category);
CREATE INDEX idx_manifest_templates_public ON manifest_templates(is_public);
CREATE INDEX idx_manifest_templates_tags ON manifest_templates USING GIN(tags);

CREATE TRIGGER update_manifest_templates_updated_at
    BEFORE UPDATE ON manifest_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 7. manifest_builder_sessions - Active/saved manifest builder sessions
CREATE TABLE IF NOT EXISTS manifest_builder_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(255) NOT NULL DEFAULT 'Untitled',
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    template_id         UUID REFERENCES manifest_templates(id) ON DELETE SET NULL,
    format              VARCHAR(30) NOT NULL DEFAULT 'compose',
    canvas_state        JSONB NOT NULL DEFAULT '{}'::jsonb,    -- positions of blocks on canvas
    services            JSONB NOT NULL DEFAULT '[]'::jsonb,    -- service definitions
    networks            JSONB NOT NULL DEFAULT '[]'::jsonb,    -- network definitions
    volumes             JSONB NOT NULL DEFAULT '[]'::jsonb,    -- volume definitions
    generated_manifest  TEXT NOT NULL DEFAULT '',               -- the rendered YAML/JSON
    validation_errors   JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_saved            BOOLEAN NOT NULL DEFAULT false,
    last_git_push_at    TIMESTAMPTZ,
    last_deploy_at      TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_manifest_builder_sessions_user ON manifest_builder_sessions(user_id);
CREATE INDEX idx_manifest_builder_sessions_format ON manifest_builder_sessions(format);
CREATE INDEX idx_manifest_builder_sessions_saved ON manifest_builder_sessions(is_saved);

CREATE TRIGGER update_manifest_builder_sessions_updated_at
    BEFORE UPDATE ON manifest_builder_sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 8. manifest_builder_components - Reusable service block library
CREATE TABLE IF NOT EXISTS manifest_builder_components (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    category        VARCHAR(100) NOT NULL DEFAULT 'general',
    icon            VARCHAR(100) NOT NULL DEFAULT '',
    default_config  JSONB NOT NULL DEFAULT '{}'::jsonb,    -- default service configuration
    ports           JSONB NOT NULL DEFAULT '[]'::jsonb,    -- default port mappings
    volumes         JSONB NOT NULL DEFAULT '[]'::jsonb,    -- default volume mounts
    environment     JSONB NOT NULL DEFAULT '[]'::jsonb,    -- default env vars
    health_check    JSONB,                                 -- default health check config
    depends_on      JSONB NOT NULL DEFAULT '[]'::jsonb,    -- suggested dependencies
    is_builtin      BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_manifest_builder_components_category ON manifest_builder_components(category);
CREATE INDEX idx_manifest_builder_components_builtin ON manifest_builder_components(is_builtin);

CREATE TRIGGER update_manifest_builder_components_updated_at
    BEFORE UPDATE ON manifest_builder_components
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
