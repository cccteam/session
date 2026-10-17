-- The driver writes every column that records when something happened with the
-- database's commit time (spanner.CommitTimestamp in a mutation,
-- PENDING_COMMIT_TIMESTAMP() in DML), never with the application's clock, so a host
-- clock that runs ahead of Spanner's cannot be refused as a timestamp in the future.
-- Such a write needs allow_commit_timestamp on the column. Apply this migration in the
-- same deploy as the driver that needs it: without it the driver's writes fail.
-- Sessions.CreatedAt and UpdatedAt are marked by the base set's 000003. ExpiresAt is
-- the caller's deadline, written as given, and stays a plain TIMESTAMP.
ALTER TABLE Sessions ALTER COLUMN AuthenticatedAt SET OPTIONS (allow_commit_timestamp = true);
ALTER TABLE SessionIdentities ALTER COLUMN CreatedAt SET OPTIONS (allow_commit_timestamp = true);
ALTER TABLE SessionIdentities ALTER COLUMN LastUsedAt SET OPTIONS (allow_commit_timestamp = true);
ALTER TABLE SessionAuthEvents ALTER COLUMN OccurredAt SET OPTIONS (allow_commit_timestamp = true);
ALTER TABLE SessionPendingSignIns ALTER COLUMN CreatedAt SET OPTIONS (allow_commit_timestamp = true);
ALTER TABLE SessionPendingSignIns ALTER COLUMN ConsumedAt SET OPTIONS (allow_commit_timestamp = true);
