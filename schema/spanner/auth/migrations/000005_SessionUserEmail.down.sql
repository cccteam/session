DROP INDEX SessionUsersByNormalizedEmail;
ALTER TABLE SessionUsers DROP COLUMN EmailVerifiedAt;
ALTER TABLE SessionUsers DROP COLUMN NormalizedEmail;
ALTER TABLE SessionUsers DROP COLUMN Email;
