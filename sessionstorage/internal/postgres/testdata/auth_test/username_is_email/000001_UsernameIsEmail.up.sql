-- Test-only: the users table in the shape of an application whose usernames are email
-- addresses, as the README's "Users and their email address" gives it. The auth set's
-- plain address columns are replaced by columns the database generates from the
-- username, so the two cannot diverge. EmailVerifiedAt stays the driver's to write.
BEGIN;
DROP INDEX "SessionUsers_NormalizedEmail_idx";
ALTER TABLE "SessionUsers" DROP COLUMN "NormalizedEmail";
ALTER TABLE "SessionUsers" DROP COLUMN "Email";
ALTER TABLE "SessionUsers" ADD COLUMN "Email" character varying GENERATED ALWAYS AS ("Username") STORED;
ALTER TABLE "SessionUsers" ADD COLUMN "NormalizedEmail" character varying GENERATED ALWAYS AS (casefold(normalize("Username"))) STORED;
CREATE UNIQUE INDEX "SessionUsers_NormalizedEmail_idx" ON "SessionUsers" USING btree ("NormalizedEmail");
COMMIT;
