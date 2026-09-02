BEGIN;

-- Table: GoogleOIDCUsers

-- DROP TABLE "GoogleOIDCUsers";

CREATE TABLE "GoogleOIDCUsers" (
  "Id"        UUID NOT NULL,
  "Sub"       character varying NOT NULL,
  "Hd"        character varying NOT NULL,
  "Username"  character varying NOT NULL,
  "CreatedAt" timestamp without time zone NOT NULL,
  "UpdatedAt" timestamp without time zone NOT NULL,
  CONSTRAINT "GoogleOIDCUsers_pkey" PRIMARY KEY ("Id")
);

-- DROP INDEX "GoogleOIDCUsers_Sub_idx";

CREATE UNIQUE INDEX "GoogleOIDCUsers_Sub_idx"
    ON "GoogleOIDCUsers" USING btree
    ("Sub");

COMMIT;
