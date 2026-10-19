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
  CONSTRAINT "SessionUsers_pkey" PRIMARY KEY ("Id")
);

CREATE UNIQUE INDEX "SessionUsers_NormalizedUsername_idx"
    ON "SessionUsers" USING btree
    ("NormalizedUsername");

COMMIT;
