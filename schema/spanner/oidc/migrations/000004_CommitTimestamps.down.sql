-- The columns keep their values; only the option goes. A driver that writes commit
-- timestamps fails against them until the up migration is applied again.
ALTER TABLE OIDCUsers ALTER COLUMN UpdatedAt SET OPTIONS (allow_commit_timestamp = null);
ALTER TABLE OIDCUsers ALTER COLUMN CreatedAt SET OPTIONS (allow_commit_timestamp = null);
ALTER TABLE Sessions ALTER COLUMN UpdatedAt SET OPTIONS (allow_commit_timestamp = null);
ALTER TABLE Sessions ALTER COLUMN CreatedAt SET OPTIONS (allow_commit_timestamp = null);
