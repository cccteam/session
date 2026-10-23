-- Test-only: the users table in the shape of an application whose usernames are email
-- addresses, as the README's "Users and their email address" gives it. The auth set's
-- plain address columns are replaced by columns the database generates from the
-- username, so the two cannot diverge. EmailVerifiedAt stays the driver's to write.
DROP INDEX SessionUsersByNormalizedEmail;
ALTER TABLE SessionUsers DROP COLUMN NormalizedEmail;
ALTER TABLE SessionUsers DROP COLUMN Email;
ALTER TABLE SessionUsers ADD COLUMN Email STRING(MAX) AS (Username) STORED;
ALTER TABLE SessionUsers ADD COLUMN NormalizedEmail STRING(MAX) AS (NORMALIZE_AND_CASEFOLD(Username)) STORED;
CREATE UNIQUE NULL_FILTERED INDEX SessionUsersByNormalizedEmail ON SessionUsers(NormalizedEmail);
