DROP TABLE SessionAuthEvents;
DROP INDEX SessionIdentitiesByUserId;
DROP INDEX SessionIdentitiesByKey;
DROP TABLE SessionIdentities;
DROP INDEX SessionsByUserId;
ALTER TABLE Sessions DROP COLUMN AuthenticatedAt;
ALTER TABLE Sessions DROP COLUMN UserId;
