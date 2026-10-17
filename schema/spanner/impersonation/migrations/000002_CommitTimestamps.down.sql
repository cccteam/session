-- The columns keep their values; only the option goes. A driver that writes commit
-- timestamps fails against them until the up migration is applied again.
ALTER TABLE SessionImpersonations ALTER COLUMN EndedAt SET OPTIONS (allow_commit_timestamp = null);
ALTER TABLE SessionImpersonations ALTER COLUMN StartedAt SET OPTIONS (allow_commit_timestamp = null);
