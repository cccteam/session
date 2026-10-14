ALTER TABLE Sessions ALTER COLUMN CreatedAt SET OPTIONS (allow_commit_timestamp = true);
ALTER TABLE Sessions ALTER COLUMN UpdatedAt SET OPTIONS (allow_commit_timestamp = true);
