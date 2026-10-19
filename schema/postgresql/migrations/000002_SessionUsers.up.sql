BEGIN;

-- Table: SessionUsers

-- DROP TABLE "SessionUsers";

CREATE TABLE "SessionUsers" (
  "Id"            UUID NOT NULL,
  "Username"      character varying NOT NULL,
  "NormalizedUsername" character varying GENERATED ALWAYS AS (casefold(normalize("Username"))) STORED,
  "PasswordHash"  character varying,
  "Disabled"      BOOL NOT NULL DEFAULT (FALSE),
  -- An operator set the password (a first password, a reset): the user changes it
  -- before anything else is served.
  "PasswordChangeRequired" BOOL NOT NULL DEFAULT (FALSE),
  -- The database's time at the insert and at the latest sign-in (null before the
  -- first); the driver writes both with now().
  "CreatedAt"     timestamp with time zone NOT NULL DEFAULT now(),
  "LastSignInAt"  timestamp with time zone,
  CONSTRAINT "SessionUsers_pkey" PRIMARY KEY ("Id")
);

-- DROP INDEX "SessionUsers_NormalizedUsername_idx";

CREATE UNIQUE INDEX "SessionUsers_NormalizedUsername_idx"
    ON "SessionUsers" USING btree
    ("NormalizedUsername");

COMMIT;