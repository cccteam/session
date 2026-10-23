BEGIN;
DROP INDEX IF EXISTS "SessionUsers_NormalizedEmail_idx";
ALTER TABLE "SessionUsers" DROP COLUMN IF EXISTS "EmailVerifiedAt";
ALTER TABLE "SessionUsers" DROP COLUMN IF EXISTS "NormalizedEmail";
ALTER TABLE "SessionUsers" DROP COLUMN IF EXISTS "Email";
COMMIT;
