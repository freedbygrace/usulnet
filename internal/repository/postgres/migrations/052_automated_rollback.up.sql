-- Automated Rollback: policies and execution history
CREATE TABLE IF NOT EXISTS rollback_policies (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stack_id              UUID NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    host_id               UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    enabled               BOOLEAN NOT NULL DEFAULT true,
    trigger_on            VARCHAR(50) NOT NULL DEFAULT 'deploy_failure',  -- deploy_failure, health_check, exit_code
    health_check_url      TEXT DEFAULT '',
    health_check_interval INTEGER NOT NULL DEFAULT 30,                    -- seconds
    health_check_timeout  INTEGER NOT NULL DEFAULT 10,                    -- seconds
    max_retries           INTEGER NOT NULL DEFAULT 3,
    cooldown_minutes      INTEGER NOT NULL DEFAULT 5,                     -- min time between rollbacks
    notify_on_rollback    BOOLEAN NOT NULL DEFAULT true,
    created_by            UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(stack_id)
);

CREATE INDEX idx_rollback_policies_stack ON rollback_policies(stack_id);
CREATE INDEX idx_rollback_policies_host ON rollback_policies(host_id);

CREATE TABLE IF NOT EXISTS rollback_executions (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id         UUID REFERENCES rollback_policies(id) ON DELETE SET NULL,
    stack_id          UUID NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    host_id           UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    trigger_reason    VARCHAR(50) NOT NULL,                              -- deploy_failure, health_check, manual
    from_version      INTEGER NOT NULL DEFAULT 0,
    to_version        INTEGER NOT NULL DEFAULT 0,
    status            VARCHAR(20) NOT NULL DEFAULT 'pending',           -- pending, rolling_back, success, failed
    output            TEXT DEFAULT '',
    error_message     TEXT DEFAULT '',
    compose_snapshot  TEXT DEFAULT '',                                   -- the compose file we rolled back to
    duration_ms       INTEGER DEFAULT 0,
    triggered_by      UUID REFERENCES users(id) ON DELETE SET NULL,     -- NULL = automatic
    started_at        TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rollback_executions_stack ON rollback_executions(stack_id);
CREATE INDEX idx_rollback_executions_policy ON rollback_executions(policy_id);
CREATE INDEX idx_rollback_executions_status ON rollback_executions(status);
CREATE INDEX idx_rollback_executions_created ON rollback_executions(created_at DESC);
