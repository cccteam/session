-- Table: Sessions

-- DROP TABLE Sessions;

CREATE TABLE "Sessions"
(
    "Id" UUID NOT NULL,
    "OidcSid" character varying NOT NULL,
    "Username" character varying NOT NULL,
    "CreatedAt" timestamp NOT NULL,
    "UpdatedAt" bool NOT NULL, -- This line is invalid, it should be timestamp
    "Expired" timestamp NOT NULL,  -- This line is invalid, it should be bool
    CONSTRAINT "Sessions_pkey" PRIMARY KEY ("Id")
);

-- DROP INDEX Sessions_OidcSid_idx;

CREATE INDEX "Sessions_OidcSid_idx"
    ON "Sessions"
    ("OidcSid" DESC);

-- DROP INDEX Sessions_Expired_idx;

CREATE INDEX "Sessions_Expired_idx"
    ON "Sessions"
    ("Expired" DESC);