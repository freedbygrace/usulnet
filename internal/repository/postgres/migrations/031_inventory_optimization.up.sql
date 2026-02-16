-- ============================================================================
-- 031_inventory_optimization: Optimized indices for multi-host inventory queries
-- ============================================================================
-- Addresses performance degradation with 1000+ containers across 50+ hosts.
-- Adds covering indices for common dashboard/list patterns and a materialized
-- view for fast host-level summary aggregation.

-- ============================================================================
-- Extension needed for trigram indices (must be created before GIN trgm indices)
-- ============================================================================
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ============================================================================
-- Composite covering indices for multi-host container queries
-- ============================================================================

-- Fast container listing filtered by host + state with name ordering (dashboard)
CREATE INDEX IF NOT EXISTS idx_containers_host_state_name
    ON containers (host_id, state, name);

-- Dashboard: quickly count containers per state across all hosts
CREATE INDEX IF NOT EXISTS idx_containers_state_host
    ON containers (state, host_id);

-- Container search by name prefix (common for autocomplete/search bar)
CREATE INDEX IF NOT EXISTS idx_containers_name_trgm
    ON containers USING gin (name gin_trgm_ops);

-- Image search by name prefix
CREATE INDEX IF NOT EXISTS idx_containers_image_trgm
    ON containers USING gin (image gin_trgm_ops);

-- ============================================================================
-- Image table: multi-host listing
-- ============================================================================

-- Fast image listing filtered by host ordered by creation date
CREATE INDEX IF NOT EXISTS idx_images_host_created
    ON images (host_id, created_at DESC);

-- ============================================================================
-- Volume table: multi-host listing
-- ============================================================================

-- Fast volume listing filtered by host ordered by creation date
CREATE INDEX IF NOT EXISTS idx_volumes_host_created
    ON volumes (host_id, created_at DESC);

-- ============================================================================
-- Network table: multi-host listing
-- ============================================================================

-- Fast network listing filtered by host and driver
CREATE INDEX IF NOT EXISTS idx_networks_host_driver
    ON networks (host_id, driver);

-- ============================================================================
-- Security scans: multi-host dashboard
-- ============================================================================

-- Fast lookup of latest scan per container per host
CREATE INDEX IF NOT EXISTS idx_security_scans_host_container_completed
    ON security_scans (host_id, container_id, completed_at DESC);

-- Grade distribution queries for dashboard
CREATE INDEX IF NOT EXISTS idx_security_scans_host_grade
    ON security_scans (host_id, grade);

-- ============================================================================
-- Host summary materialized view for dashboard
-- ============================================================================

-- Provides pre-aggregated counts per host, refreshed periodically via scheduler.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_host_inventory_summary AS
SELECT
    h.id                                             AS host_id,
    h.name                                           AS host_name,
    h.status                                         AS host_status,
    COUNT(c.id) FILTER (WHERE c.id IS NOT NULL)      AS total_containers,
    COUNT(c.id) FILTER (WHERE c.state = 'running')   AS running_containers,
    COUNT(c.id) FILTER (WHERE c.state = 'exited')    AS stopped_containers,
    COUNT(c.id) FILTER (WHERE c.state = 'paused')    AS paused_containers,
    COUNT(c.id) FILTER (WHERE c.update_available)    AS update_available_count,
    COALESCE(AVG(c.security_score) FILTER (WHERE c.security_score > 0), 0)
                                                     AS avg_security_score,
    (SELECT COUNT(*) FROM images i WHERE i.host_id = h.id)   AS total_images,
    (SELECT COUNT(*) FROM volumes v WHERE v.host_id = h.id)  AS total_volumes,
    (SELECT COUNT(*) FROM networks n WHERE n.host_id = h.id) AS total_networks,
    NOW()                                            AS refreshed_at
FROM hosts h
LEFT JOIN containers c ON c.host_id = h.id
GROUP BY h.id, h.name, h.status;

-- Unique index required for REFRESH MATERIALIZED VIEW CONCURRENTLY
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_host_inventory_summary_host
    ON mv_host_inventory_summary (host_id);

-- ============================================================================
-- Function to refresh the materialized view safely
-- ============================================================================
CREATE OR REPLACE FUNCTION refresh_host_inventory_summary()
RETURNS VOID AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_host_inventory_summary;
END;
$$ LANGUAGE plpgsql;

COMMENT ON MATERIALIZED VIEW mv_host_inventory_summary IS 'Pre-aggregated host inventory counts for dashboard. Refresh via scheduler or refresh_host_inventory_summary()';
COMMENT ON FUNCTION refresh_host_inventory_summary IS 'Safely refresh host inventory summary materialized view (concurrent, non-blocking)';

