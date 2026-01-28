BEGIN;

-- Table: SessionUsers

-- DROP TABLE "SessionUsers";

CREATE TABLE "SessionUsers" (
  "Id"            UUID NOT NULL,
  "Username"      character varying NOT NULL,
  "NormalizedUsername" character varying GENERATED ALWAYS AS (casefold(normalize("Username"))) STORED,
  "PasswordHash"  character varying,
  "Disabled"      BOOL NOT NULL DEFAULT (FALSE),
  CONSTRAINT "SessionUsers_pkey" PRIMARY KEY ("Id")
);

-- DROP INDEX "SessionUsers_NormalizedUsername_idx";

CREATE UNIQUE INDEX "SessionUsers_NormalizedUsername_idx"
    ON "SessionUsers" USING btree
    ("NormalizedUsername");

COMMIT;