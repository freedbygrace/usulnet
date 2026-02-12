-- Migration 027: GitOps Market Expansion (Phase 3)
-- Adds tables for: bidirectional git sync, ephemeral environments, manifest builder.

-- Drop triggers first
DROP TRIGGER IF EXISTS update_manifest_builder_components_updated_at ON manifest_builder_components;
DROP TRIGGER IF EXISTS update_manifest_builder_sessions_updated_at ON manifest_builder_sessions;
DROP TRIGGER IF EXISTS update_manifest_templates_updated_at ON manifest_templates;
DROP TRIGGER IF EXISTS update_ephemeral_environments_updated_at ON ephemeral_environments;
DROP TRIGGER IF EXISTS update_git_sync_configs_updated_at ON git_sync_configs;

-- Drop tables in reverse dependency order

-- C) Manifest Builder
DROP TABLE IF EXISTS manifest_builder_components CASCADE;
DROP TABLE IF EXISTS manifest_builder_sessions CASCADE;
DROP TABLE IF EXISTS manifest_templates CASCADE;

-- B) Ephemeral Environments
DROP TABLE IF EXISTS ephemeral_environment_logs CASCADE;
DROP TABLE IF EXISTS ephemeral_environments CASCADE;

-- A) Bidirectional Git Sync
DROP TABLE IF EXISTS git_sync_conflicts CASCADE;
DROP TABLE IF EXISTS git_sync_events CASCADE;
DROP TABLE IF EXISTS git_sync_configs CASCADE;
