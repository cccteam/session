-- Accounts schema for Auth sessions (multi-method sessions, v0.13.0).
-- Applies on top of the base migrations set (Sessions, SessionUsers).
BEGIN;

ALTER TABLE "Sessions" ADD COLUMN "UserId" UUID;
ALTER TABLE "Sessions" ADD COLUMN "AuthenticatedAt" timestamp with time zone;

CREATE INDEX "Sessions_UserId_idx" ON "Sessions" USING btree ("UserId");

CREATE TABLE "SessionIdentities"
(
    "Id" UUID NOT NULL,
    "UserId" UUID NOT NULL,
    "Method" character varying(32) NOT NULL,
    "Connection" character varying NOT NULL,
    "Subject" character varying NOT NULL,
    "Tenant" character varying,
    "EmailAtLink" character varying,
    "CreatedAt" timestamp with time zone NOT NULL,
    "LastUsedAt" timestamp with time zone NOT NULL,
    CONSTRAINT "SessionIdentities_pkey" PRIMARY KEY ("Id"),
    CONSTRAINT "SessionIdentities_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id")
);

CREATE UNIQUE INDEX "SessionIdentities_Key_idx" ON "SessionIdentities" USING btree ("Method", "Connection", "Subject");
CREATE INDEX "SessionIdentities_UserId_idx" ON "SessionIdentities" USING btree ("UserId");

CREATE TABLE "SessionAuthEvents"
(
    "SessionId" UUID NOT NULL,
    "Seq" bigint NOT NULL,
    "Method" character varying(32) NOT NULL,
    "Connection" character varying,
    "IdpAmr" character varying[],
    "At" timestamp with time zone NOT NULL,
    CONSTRAINT "SessionAuthEvents_pkey" PRIMARY KEY ("SessionId", "Seq"),
    CONSTRAINT "SessionAuthEvents_SessionId_fkey" FOREIGN KEY ("SessionId") REFERENCES "Sessions" ("Id") ON DELETE CASCADE
);

COMMIT;
