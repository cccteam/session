-- The driver writes every column that records when something happened with the
-- database's commit time (spanner.CommitTimestamp in a mutation,
-- PENDING_COMMIT_TIMESTAMP() in DML), never with the application's clock, so a host
-- clock that runs ahead of Spanner's cannot be refused as a timestamp in the future.
-- Such a write needs allow_commit_timestamp on the column. Apply this migration in the
-- same deploy as the driver that needs it: without it the driver's writes fail.
ALTER TABLE Sessions ALTER COLUMN CreatedAt SET OPTIONS (allow_commit_timestamp = true);
ALTER TABLE Sessions ALTER COLUMN UpdatedAt SET OPTIONS (allow_commit_timestamp = true);
