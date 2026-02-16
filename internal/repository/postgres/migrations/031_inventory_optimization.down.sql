-- Rollback 031_inventory_optimization

DROP FUNCTION IF EXISTS refresh_host_inventory_summary();
DROP MATERIALIZED VIEW IF EXISTS mv_host_inventory_summary;

DROP INDEX IF EXISTS idx_security_scans_host_grade;
DROP INDEX IF EXISTS idx_security_scans_host_container_completed;
DROP INDEX IF EXISTS idx_networks_host_driver;
DROP INDEX IF EXISTS idx_volumes_host_created;
DROP INDEX IF EXISTS idx_images_host_created;
DROP INDEX IF EXISTS idx_containers_image_trgm;
DROP INDEX IF EXISTS idx_containers_name_trgm;
DROP INDEX IF EXISTS idx_containers_state_host;
DROP INDEX IF EXISTS idx_containers_host_state_name;
