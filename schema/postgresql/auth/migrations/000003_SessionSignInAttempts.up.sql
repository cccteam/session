-- Sign-in attempts: the failed password attempts on one name, known or not, within a
-- window, and the lock those failures earned. The row is keyed by the submitted name as
-- the users table normalizes usernames, never by the user row, so an unknown name is
-- counted exactly as a known one. Failures counts in the window ending at WindowEndsAt;
-- LockedUntil is set once Failures reached the limit, and the name is refused until
-- then. A success, an MFA completion or a password change deletes the row.
BEGIN;

CREATE TABLE "SessionSignInAttempts"
(
    "Name" character varying NOT NULL,
    "Failures" bigint NOT NULL,
    "WindowEndsAt" timestamp with time zone NOT NULL,
    "LockedUntil" timestamp with time zone,
    "UpdatedAt" timestamp with time zone NOT NULL,
    CONSTRAINT "SessionSignInAttempts_pkey" PRIMARY KEY ("Name")
);

COMMIT;
