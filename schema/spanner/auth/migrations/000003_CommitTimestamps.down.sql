-- The columns keep their values; only the option goes. A driver that writes commit
-- timestamps fails against them until the up migration is applied again.
ALTER TABLE SessionPendingSignIns ALTER COLUMN ConsumedAt SET OPTIONS (allow_commit_timestamp = null);
ALTER TABLE SessionPendingSignIns ALTER COLUMN CreatedAt SET OPTIONS (allow_commit_timestamp = null);
ALTER TABLE SessionAuthEvents ALTER COLUMN OccurredAt SET OPTIONS (allow_commit_timestamp = null);
ALTER TABLE SessionIdentities ALTER COLUMN LastUsedAt SET OPTIONS (allow_commit_timestamp = null);
ALTER TABLE SessionIdentities ALTER COLUMN CreatedAt SET OPTIONS (allow_commit_timestamp = null);
ALTER TABLE Sessions ALTER COLUMN AuthenticatedAt SET OPTIONS (allow_commit_timestamp = null);
