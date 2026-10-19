-- Upgrade of a legacy Azure (oidc set) group to the Auth schema, step 1 of 4: the users
-- table, the same as the base set's. Apply the whole set at the cutover to Auth; the
-- legacy OIDCAzure type does not serve the group afterwards.
BEGIN;

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

CREATE UNIQUE INDEX "SessionUsers_NormalizedUsername_idx"
    ON "SessionUsers" USING btree
    ("NormalizedUsername");

COMMIT;
