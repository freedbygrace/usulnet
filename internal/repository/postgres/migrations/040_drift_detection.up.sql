-- Migration 040: Drift Detection
-- Phase 4: Configuration snapshots and drift detection for container resources

CREATE TABLE IF NOT EXISTS configuration_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type   VARCHAR(100) NOT NULL,
    resource_id     VARCHAR(255) NOT NULL,
    resource_name   VARCHAR(512) NOT NULL DEFAULT '',
    status          VARCHAR(50) NOT NULL DEFAULT 'current',
    snapshot        JSONB NOT NULL,
    taken_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    taken_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    note            TEXT NOT NULL DEFAULT ''
);

-- Composite index for looking up snapshots by resource and status
CREATE INDEX IF NOT EXISTS idx_configuration_snapshots_resource_status
    ON configuration_snapshots (resource_type, resource_id, status);

-- Chronological listing
CREATE INDEX IF NOT EXISTS idx_configuration_snapshots_taken_at
    ON configuration_snapshots (taken_at DESC);

-- Fast baseline lookup
CREATE INDEX IF NOT EXISTS idx_configuration_snapshots_baseline
    ON configuration_snapshots (status)
    WHERE status = 'baseline';

CREATE TABLE IF NOT EXISTS drift_detections (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type         VARCHAR(100) NOT NULL,
    resource_id           VARCHAR(255) NOT NULL,
    resource_name         VARCHAR(512) NOT NULL DEFAULT '',
    baseline_snapshot_id  UUID REFERENCES configuration_snapshots(id) ON DELETE SET NULL,
    current_snapshot_id   UUID REFERENCES configuration_snapshots(id) ON DELETE SET NULL,
    status                VARCHAR(50) NOT NULL DEFAULT 'open',
    severity              VARCHAR(20) NOT NULL DEFAULT 'warning',
    diffs                 JSONB NOT NULL DEFAULT '[]',
    diff_count            INTEGER NOT NULL DEFAULT 0,
    detected_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at           TIMESTAMPTZ,
    resolved_by           UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution_note       TEXT NOT NULL DEFAULT ''
);

-- Primary lookup: drift history per resource
CREATE INDEX IF NOT EXISTS idx_drift_detections_resource
    ON drift_detections (resource_type, resource_id, detected_at DESC);

-- Filter by status (open, accepted, remediated)
CREATE INDEX IF NOT EXISTS idx_drift_detections_status
    ON drift_detections (status);

-- Filter by severity (critical, warning, info)
CREATE INDEX IF NOT EXISTS idx_drift_detections_severity
    ON drift_detections (severity);

-- Chronological listing
CREATE INDEX IF NOT EXISTS idx_drift_detections_detected_at
    ON drift_detections (detected_at DESC);
