-- Auth schema for Auth sessions (multi-method sessions, v0.13.0).
-- Applies on top of the base migrations set (Sessions, SessionUsers). An application
-- whose tables are named per auth group applies it under its own names.
--
-- A session belongs to a user (UserId, null only for a role-principal impersonation),
-- and deleting the user deletes its sessions, their auth events and its identity links.
-- ProviderSessionId is the identity provider's session id when the method reports one,
-- for front-channel logout; it is nullable on every Auth sessions table so that a
-- method added later needs no DDL.
BEGIN;

ALTER TABLE "Sessions" ADD COLUMN "UserId" UUID;
ALTER TABLE "Sessions" ADD COLUMN "AuthenticatedAt" timestamp with time zone;
ALTER TABLE "Sessions" ADD COLUMN "ProviderSessionId" character varying;
ALTER TABLE "Sessions" ADD CONSTRAINT "Sessions_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id") ON DELETE CASCADE;

CREATE INDEX "Sessions_UserId_idx" ON "Sessions" USING btree ("UserId");
CREATE INDEX "Sessions_ProviderSessionId_idx" ON "Sessions" USING btree ("ProviderSessionId");

CREATE TABLE "SessionIdentities"
(
    "Id" UUID NOT NULL,
    "UserId" UUID NOT NULL,
    "Method" character varying NOT NULL,
    "Connection" character varying NOT NULL,
    "Subject" character varying NOT NULL,
    "Tenant" character varying,
    "EmailAtLink" character varying,
    "CreatedAt" timestamp with time zone NOT NULL,
    "LastUsedAt" timestamp with time zone NOT NULL,
    CONSTRAINT "SessionIdentities_pkey" PRIMARY KEY ("Id"),
    CONSTRAINT "SessionIdentities_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX "SessionIdentities_Key_idx" ON "SessionIdentities" USING btree ("Method", "Connection", "Subject");
CREATE INDEX "SessionIdentities_UserId_idx" ON "SessionIdentities" USING btree ("UserId");

CREATE TABLE "SessionAuthEvents"
(
    "SessionId" UUID NOT NULL,
    "Seq" bigint NOT NULL,
    "Method" character varying NOT NULL,
    "Connection" character varying,
    "IdpAmr" character varying[],
    "OccurredAt" timestamp with time zone NOT NULL,
    CONSTRAINT "SessionAuthEvents_pkey" PRIMARY KEY ("SessionId", "Seq"),
    CONSTRAINT "SessionAuthEvents_SessionId_fkey" FOREIGN KEY ("SessionId") REFERENCES "Sessions" ("Id") ON DELETE CASCADE
);

COMMIT;
