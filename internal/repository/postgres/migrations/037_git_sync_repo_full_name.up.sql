-- Add repo_full_name to git_sync_configs so that sync operations can use the
-- actual Git repository identifier (e.g. "org/repo") instead of the config's
-- human-readable name.
ALTER TABLE git_sync_configs
    ADD COLUMN repo_full_name VARCHAR(512) NOT NULL DEFAULT '';

-- Backfill existing rows from the gitea_repositories table.
UPDATE git_sync_configs gsc
SET repo_full_name = gr.full_name
FROM gitea_repositories gr
WHERE gsc.repository_id = gr.id
  AND gsc.repo_full_name = '';

-- Add repo_full_name to ephemeral_environments so that provisioning can use
-- the actual Git repository identifier when fetching compose files.
ALTER TABLE ephemeral_environments
    ADD COLUMN repo_full_name VARCHAR(512) NOT NULL DEFAULT '';

-- Backfill existing rows from the gitea_repositories table.
UPDATE ephemeral_environments ee
SET repo_full_name = gr.full_name
FROM gitea_repositories gr
WHERE ee.repository_id = gr.id
  AND ee.repo_full_name = '';
