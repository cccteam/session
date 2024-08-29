-- Table: Sessions

-- DROP TABLE IF EXISTS Sessions;

CREATE TABLE IF NOT EXISTS "Sessions"
(
    "Id" character varying NOT NULL,
    "OidcSid" character varying NOT NULL,
    "Username" character varying NOT NULL,
    "CreatedAt" timestamp NOT NULL,
    "UpdatedAt" bool NOT NULL, -- This line is invalid, it should be timestamp
    "Expired" timestamp NOT NULL,  -- This line is invalid, it should be bool
    CONSTRAINT "Sessions_pkey" PRIMARY KEY ("Id")
);

-- DROP INDEX IF EXISTS Sessions_OidcSid_idx;

CREATE INDEX IF NOT EXISTS "Sessions_OidcSid_idx"
    ON "Sessions"
    ("OidcSid" DESC);

-- DROP INDEX IF EXISTS Sessions_Expired_idx;

CREATE INDEX IF NOT EXISTS "Sessions_Expired_idx"
    ON "Sessions"
    ("Expired" DESC);