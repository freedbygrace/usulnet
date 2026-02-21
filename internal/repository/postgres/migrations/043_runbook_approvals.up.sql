-- Runbook approval tracking
CREATE TABLE IF NOT EXISTS runbook_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL REFERENCES runbook_executions(id) ON DELETE CASCADE,
    step_order INT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMPTZ,
    responded_by UUID REFERENCES users(id),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_runbook_approvals_execution ON runbook_approvals(execution_id);
CREATE INDEX IF NOT EXISTS idx_runbook_approvals_pending ON runbook_approvals(status) WHERE status = 'pending';
