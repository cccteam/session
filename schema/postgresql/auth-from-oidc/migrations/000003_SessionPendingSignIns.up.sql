-- Step 3 of 4: the pending sign-ins table, as the auth set creates it.
-- Pending sign-ins: a sign-in that waits for a password confirmation or the
-- application's MFA step, held server-side. The browser's pending cookie carries only an
-- opaque token; TokenHash is its SHA-256. A row is live until ExpiresAt or until a
-- completion, cancellation or replacement consumes it (ConsumedAt), once.
BEGIN;

CREATE TABLE "SessionPendingSignIns"
(
    "Id" UUID NOT NULL,
    "TokenHash" bytea NOT NULL,
    "Step" character varying(16) NOT NULL,
    "Registration" character varying NOT NULL,
    "Method" character varying NOT NULL,
    "Connection" character varying NOT NULL,
    "Subject" character varying NOT NULL,
    "Email" character varying NOT NULL,
    "EmailVerified" boolean NOT NULL,
    "IdpAmr" character varying[],
    "Claims" bytea,
    "UserId" UUID,
    "Username" character varying NOT NULL,
    "Tenant" character varying NOT NULL,
    "Events" bytea NOT NULL,
    "RoleNames" character varying[],
    "Factors" character varying[],
    "ReturnUrl" character varying NOT NULL,
    "CreatedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "ConsumedAt" timestamp with time zone,
    CONSTRAINT "SessionPendingSignIns_pkey" PRIMARY KEY ("Id"),
    CONSTRAINT "SessionPendingSignIns_Step_check" CHECK ("Step" IN ('confirmation', 'mfa'))
);

CREATE UNIQUE INDEX "SessionPendingSignIns_TokenHash_idx" ON "SessionPendingSignIns" USING btree ("TokenHash");
CREATE INDEX "SessionPendingSignIns_ExpiresAt_idx" ON "SessionPendingSignIns" USING btree ("ExpiresAt");

COMMIT;
