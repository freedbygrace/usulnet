-- ============================================================================
-- 024_fix_schema_mismatches: Reverse migration
-- ============================================================================

-- Reverse auto_deploy_rules changes
ALTER TABLE auto_deploy_rules DROP COLUMN IF EXISTS source_repo;
ALTER TABLE auto_deploy_rules DROP COLUMN IF EXISTS source_branch;
ALTER TABLE auto_deploy_rules DROP COLUMN IF EXISTS target_stack_id;
ALTER TABLE auto_deploy_rules DROP COLUMN IF EXISTS target_service;
ALTER TABLE auto_deploy_rules DROP COLUMN IF EXISTS last_triggered_at;

-- Reverse runbook_executions changes
ALTER TABLE runbook_executions DROP COLUMN IF EXISTS trigger;
ALTER TABLE runbook_executions DROP COLUMN IF EXISTS trigger_ref;
ALTER TABLE runbook_executions DROP COLUMN IF EXISTS step_results;
ALTER TABLE runbook_executions DROP COLUMN IF EXISTS finished_at;
ALTER TABLE runbook_executions DROP COLUMN IF EXISTS executed_by;
ALTER TABLE runbook_executions DROP COLUMN IF EXISTS created_at;

-- Reverse runbooks changes
ALTER TABLE runbooks DROP COLUMN IF EXISTS category;
ALTER TABLE runbooks DROP COLUMN IF EXISTS version;

-- Reverse webhook_deliveries changes
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS event;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS payload;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS error;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS attempt;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS delivered_at;

-- Reverse outgoing_webhooks rename
ALTER TABLE outgoing_webhooks RENAME COLUMN timeout_secs TO timeout;

-- Reverse scheduled_jobs.target_id type change
ALTER TABLE scheduled_jobs ALTER COLUMN target_id TYPE UUID USING target_id::UUID;

-- Reverse jobs changes
DROP INDEX IF EXISTS idx_jobs_target;
ALTER TABLE jobs ALTER COLUMN target_id TYPE UUID USING target_id::UUID;
CREATE INDEX idx_jobs_target ON jobs(target_type, target_id);
ALTER TABLE jobs DROP COLUMN IF EXISTS scheduled_at;
ALTER TABLE jobs DROP COLUMN IF EXISTS target_name;
