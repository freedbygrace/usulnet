-- ============================================================================
-- 024_fix_schema_mismatches: Align database schema with repository code
-- ============================================================================

-- ============================================================================
-- Fix jobs table
-- ============================================================================
-- Add missing columns expected by repository code
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS target_name VARCHAR(255);
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ;
-- Change target_id from UUID to TEXT for flexible ID storage
-- (container IDs are hex strings, stack names are strings, etc.)
DROP INDEX IF EXISTS idx_jobs_target;
ALTER TABLE jobs ALTER COLUMN target_id TYPE TEXT USING target_id::TEXT;
CREATE INDEX idx_jobs_target ON jobs(target_type, target_id);

-- Fix scheduled_jobs.target_id to TEXT for consistency
ALTER TABLE scheduled_jobs ALTER COLUMN target_id TYPE TEXT USING target_id::TEXT;

-- ============================================================================
-- Fix outgoing_webhooks table
-- ============================================================================
-- Rename timeout to timeout_secs to match model db tag
ALTER TABLE outgoing_webhooks RENAME COLUMN timeout TO timeout_secs;

-- ============================================================================
-- Fix webhook_deliveries table
-- ============================================================================
-- Add columns expected by repository code (simplified delivery model)
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS event VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS payload JSONB;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS error TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS attempt INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ;

-- ============================================================================
-- Fix runbooks table
-- ============================================================================
-- Add columns expected by repository code
ALTER TABLE runbooks ADD COLUMN IF NOT EXISTS category VARCHAR(100) NOT NULL DEFAULT '';
ALTER TABLE runbooks ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;

-- ============================================================================
-- Fix runbook_executions table
-- ============================================================================
-- Add columns expected by repository code
ALTER TABLE runbook_executions ADD COLUMN IF NOT EXISTS trigger VARCHAR(32) NOT NULL DEFAULT 'manual';
ALTER TABLE runbook_executions ADD COLUMN IF NOT EXISTS trigger_ref TEXT;
ALTER TABLE runbook_executions ADD COLUMN IF NOT EXISTS step_results JSONB;
ALTER TABLE runbook_executions ADD COLUMN IF NOT EXISTS finished_at TIMESTAMPTZ;
ALTER TABLE runbook_executions ADD COLUMN IF NOT EXISTS executed_by UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE runbook_executions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- ============================================================================
-- Fix auto_deploy_rules table
-- ============================================================================
-- Add columns expected by repository code
ALTER TABLE auto_deploy_rules ADD COLUMN IF NOT EXISTS source_repo VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE auto_deploy_rules ADD COLUMN IF NOT EXISTS source_branch VARCHAR(255);
ALTER TABLE auto_deploy_rules ADD COLUMN IF NOT EXISTS target_stack_id VARCHAR(255);
ALTER TABLE auto_deploy_rules ADD COLUMN IF NOT EXISTS target_service VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE auto_deploy_rules ADD COLUMN IF NOT EXISTS last_triggered_at TIMESTAMPTZ;
