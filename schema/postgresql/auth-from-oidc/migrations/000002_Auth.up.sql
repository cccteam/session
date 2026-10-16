-- Step 2 of 4: the Auth columns and tables, as the auth set creates them, on the
-- legacy Azure sessions table. OidcSid becomes ProviderSessionId, nullable: Auth
-- records the provider's session id when the method reports one, with its issuer in
-- ProviderSessionIssuer. The legacy sessions keep their id but have no issuer, and a
-- logout matches both, so a later Entra logout cannot reach them until the person
-- signs in again.
BEGIN;

ALTER TABLE "Sessions" RENAME COLUMN "OidcSid" TO "ProviderSessionId";
ALTER TABLE "Sessions" ALTER COLUMN "ProviderSessionId" DROP NOT NULL;
ALTER INDEX "Sessions_OidcSid_idx" RENAME TO "Sessions_ProviderSessionId_idx";
ALTER TABLE "Sessions" ADD COLUMN "ProviderSessionIssuer" character varying;

ALTER TABLE "Sessions" ADD COLUMN "UserId" UUID;
ALTER TABLE "Sessions" ADD COLUMN "AuthenticatedAt" timestamp with time zone;
ALTER TABLE "Sessions" ADD CONSTRAINT "Sessions_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id") ON DELETE CASCADE;

CREATE INDEX "Sessions_UserId_idx" ON "Sessions" USING btree ("UserId");

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
