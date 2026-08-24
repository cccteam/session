BEGIN;

-- Table: OIDCUsers

-- DROP TABLE "OIDCUsers";

CREATE TABLE "OIDCUsers" (
  "Id"        UUID NOT NULL,
  "Tid"       character varying NOT NULL,
  "Oid"       character varying NOT NULL,
  "Username"  character varying NOT NULL,
  "CreatedAt" timestamp without time zone NOT NULL,
  "UpdatedAt" timestamp without time zone NOT NULL,
  CONSTRAINT "OIDCUsers_pkey" PRIMARY KEY ("Id")
);

-- DROP INDEX "OIDCUsers_Tid_Oid_idx";

CREATE UNIQUE INDEX "OIDCUsers_Tid_Oid_idx"
    ON "OIDCUsers" USING btree
    ("Tid", "Oid");

COMMIT;
