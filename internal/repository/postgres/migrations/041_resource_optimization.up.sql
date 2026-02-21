-- Migration 041: Cost/Resource Optimization — usage samples, aggregations, recommendations

-- Time-series container resource usage samples
CREATE TABLE IF NOT EXISTS resource_usage_samples (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    container_id        VARCHAR(255) NOT NULL,
    container_name      VARCHAR(512) NOT NULL DEFAULT '',
    host_id             VARCHAR(255) NOT NULL DEFAULT '',
    sampled_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cpu_usage_percent   DOUBLE PRECISION NOT NULL DEFAULT 0,
    cpu_peak_percent    DOUBLE PRECISION NOT NULL DEFAULT 0,
    memory_usage_bytes  BIGINT NOT NULL DEFAULT 0,
    memory_limit_bytes  BIGINT NOT NULL DEFAULT 0,
    memory_peak_bytes   BIGINT NOT NULL DEFAULT 0,
    network_rx_bytes    BIGINT NOT NULL DEFAULT 0,
    network_tx_bytes    BIGINT NOT NULL DEFAULT 0,
    disk_read_bytes     BIGINT NOT NULL DEFAULT 0,
    disk_write_bytes    BIGINT NOT NULL DEFAULT 0,
    pids_current        INTEGER NOT NULL DEFAULT 0
);

-- Lookup by container over time
CREATE INDEX IF NOT EXISTS idx_resource_usage_samples_container_time
    ON resource_usage_samples (container_id, sampled_at DESC);

-- Chronological listing / cleanup
CREATE INDEX IF NOT EXISTS idx_resource_usage_samples_sampled_at
    ON resource_usage_samples (sampled_at DESC);

-- Hourly aggregated resource usage
CREATE TABLE IF NOT EXISTS resource_usage_hourly (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    container_id        VARCHAR(255) NOT NULL,
    container_name      VARCHAR(512) NOT NULL DEFAULT '',
    hour                TIMESTAMPTZ NOT NULL,
    cpu_avg             DOUBLE PRECISION NOT NULL DEFAULT 0,
    cpu_peak            DOUBLE PRECISION NOT NULL DEFAULT 0,
    memory_avg_bytes    BIGINT NOT NULL DEFAULT 0,
    memory_peak_bytes   BIGINT NOT NULL DEFAULT 0,
    memory_limit_bytes  BIGINT NOT NULL DEFAULT 0,
    network_rx_total    BIGINT NOT NULL DEFAULT 0,
    network_tx_total    BIGINT NOT NULL DEFAULT 0,
    sample_count        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (container_id, hour)
);

-- Lookup by container over time
CREATE INDEX IF NOT EXISTS idx_resource_usage_hourly_container_hour
    ON resource_usage_hourly (container_id, hour DESC);

-- Daily aggregated resource usage
CREATE TABLE IF NOT EXISTS resource_usage_daily (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    container_id        VARCHAR(255) NOT NULL,
    container_name      VARCHAR(512) NOT NULL DEFAULT '',
    day                 TIMESTAMPTZ NOT NULL,
    cpu_avg             DOUBLE PRECISION NOT NULL DEFAULT 0,
    cpu_peak            DOUBLE PRECISION NOT NULL DEFAULT 0,
    memory_avg_bytes    BIGINT NOT NULL DEFAULT 0,
    memory_peak_bytes   BIGINT NOT NULL DEFAULT 0,
    memory_limit_bytes  BIGINT NOT NULL DEFAULT 0,
    network_rx_total    BIGINT NOT NULL DEFAULT 0,
    network_tx_total    BIGINT NOT NULL DEFAULT 0,
    sample_count        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (container_id, day)
);

-- Lookup by container over time
CREATE INDEX IF NOT EXISTS idx_resource_usage_daily_container_day
    ON resource_usage_daily (container_id, day DESC);

-- Optimization recommendations
CREATE TABLE IF NOT EXISTS resource_recommendations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    container_id        VARCHAR(255) NOT NULL,
    container_name      VARCHAR(512) NOT NULL DEFAULT '',
    type                VARCHAR(100) NOT NULL,
    severity            VARCHAR(20) NOT NULL DEFAULT 'info',
    status              VARCHAR(50) NOT NULL DEFAULT 'open',
    current_value       VARCHAR(255) NOT NULL DEFAULT '',
    recommended_value   VARCHAR(255) NOT NULL DEFAULT '',
    estimated_savings   VARCHAR(255) NOT NULL DEFAULT '',
    reason              TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ,
    resolved_by         UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Lookup by container
CREATE INDEX IF NOT EXISTS idx_resource_recommendations_container
    ON resource_recommendations (container_id);

-- Filter by status (open, applied, dismissed)
CREATE INDEX IF NOT EXISTS idx_resource_recommendations_status
    ON resource_recommendations (status);

-- Filter by type
CREATE INDEX IF NOT EXISTS idx_resource_recommendations_type
    ON resource_recommendations (type);

-- Chronological listing
CREATE INDEX IF NOT EXISTS idx_resource_recommendations_created_at
    ON resource_recommendations (created_at DESC);

-- Cleanup function: removes raw samples older than the given retention period
CREATE OR REPLACE FUNCTION cleanup_old_usage_samples(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM resource_usage_samples
    WHERE sampled_at < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
