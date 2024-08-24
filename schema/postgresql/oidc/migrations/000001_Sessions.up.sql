BEGIN;

-- Table: Sessions

-- DROP TABLE IF EXISTS "Sessions";

CREATE TABLE IF NOT EXISTS "Sessions"
(
    "Id" character varying NOT NULL,
    "OidcSid" character varying NOT NULL,
    "Username" character varying NOT NULL,
    "CreatedAt" timestamp without time zone NOT NULL,
    "UpdatedAt" timestamp without time zone NOT NULL,
    "Expired" boolean NOT NULL,
    CONSTRAINT "Sessions_pkey" PRIMARY KEY ("Id")
);

-- DROP INDEX IF EXISTS "Sessions_OidcSid_idx";

CREATE INDEX IF NOT EXISTS "Sessions_OidcSid_idx"
    ON "Sessions" USING btree
    ("OidcSid" ASC NULLS LAST);

-- DROP INDEX IF EXISTS "Sessions_Expired_idx";

CREATE INDEX IF NOT EXISTS "Sessions_Expired_idx"
    ON "Sessions" USING btree
    ("Expired" ASC NULLS LAST);

COMMIT;