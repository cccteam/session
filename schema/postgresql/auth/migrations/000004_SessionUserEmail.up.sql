-- The email address on a user, in two states. Email is the address as the person gave
-- it, NormalizedEmail the form uniqueness and lookups use, and EmailVerifiedAt the
-- database's time at which the person proved they read the mailbox by following a link
-- sent to it; null while the address is unverified. An address is trusted for nothing
-- until it is verified: code that sends a link may use an unverified address, code that
-- relies on one (linking a social identity, a recovery) requires the time. An
-- administrator may put an address on a user by hand, unverified, which reserves it:
-- uniqueness holds among every address held, verified or not. No address is required.
--
-- An application whose usernames are email addresses declares the two as one value
-- instead, generated from the username by the database so they cannot diverge; the
-- README's "Users and their email address" gives that DDL in place of the first two
-- statements here.
BEGIN;

ALTER TABLE "SessionUsers" ADD COLUMN "Email" character varying;
ALTER TABLE "SessionUsers" ADD COLUMN "NormalizedEmail" character varying GENERATED ALWAYS AS (casefold(normalize("Email"))) STORED;
ALTER TABLE "SessionUsers" ADD COLUMN "EmailVerifiedAt" timestamp with time zone;
CREATE UNIQUE INDEX "SessionUsers_NormalizedEmail_idx" ON "SessionUsers" USING btree ("NormalizedEmail");

COMMIT;
