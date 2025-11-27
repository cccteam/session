BEGIN;

-- Table: SessionUsers

-- DROP TABLE "SessionUsers";

CREATE TABLE "SessionUsers" (
  "Id"            UUID NOT NULL,
  "Username"      character varying NOT NULL,
  "PasswordHash"  character varying,
  "Disabled"      BOOL NOT NULL DEFAULT (FALSE),
  CONSTRAINT "SessionUsers_pkey" PRIMARY KEY ("Id")
);

-- DROP INDEX "SessionUsers_Username_idx";

CREATE INDEX "SessionUsers_Username_idx"
    ON "SessionUsers" USING btree
    ("Username");

COMMIT;