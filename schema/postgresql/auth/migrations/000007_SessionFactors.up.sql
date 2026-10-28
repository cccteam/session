-- Factor codes and trusted devices: the second factor the library runs. A factor code
-- is one code mailed for a pending sign-in (PendingId): the mail carries the code and
-- the row keeps its hash; the row is live while it is not consumed and not expired,
-- Attempts counts the wrong codes entered against it, and a new code for the same
-- pending sign-in consumes the earlier one. A trusted device is a browser the person
-- asked to be remembered after a second factor (UserId): the browser holds an opaque
-- token in a cookie and the row keeps its hash; it stands in for the factor while it is
-- not revoked and not expired. A code goes with its pending sign-in and a device with
-- its user. CreatedAt, ConsumedAt, LastUsedAt and RevokedAt take the transaction's
-- time; ExpiresAt is the library's deadline, written as given.
BEGIN;

CREATE TABLE "SessionFactorCodes"
(
    "Id" UUID NOT NULL,
    "PendingId" UUID NOT NULL,
    "Email" character varying NOT NULL,
    "CodeHash" bytea NOT NULL,
    "Attempts" integer NOT NULL DEFAULT 0,
    "CreatedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "ConsumedAt" timestamp with time zone,
    CONSTRAINT "SessionFactorCodes_pkey" PRIMARY KEY ("Id"),
    CONSTRAINT "SessionFactorCodes_PendingId_fkey" FOREIGN KEY ("PendingId") REFERENCES "SessionPendingSignIns" ("Id") ON DELETE CASCADE
);

CREATE INDEX "SessionFactorCodes_PendingId_idx" ON "SessionFactorCodes" USING btree ("PendingId", "ConsumedAt", "ExpiresAt");

CREATE TABLE "SessionTrustedDevices"
(
    "Id" UUID NOT NULL,
    "UserId" UUID NOT NULL,
    "TokenHash" bytea NOT NULL,
    "CreatedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "LastUsedAt" timestamp with time zone,
    "RevokedAt" timestamp with time zone,
    CONSTRAINT "SessionTrustedDevices_pkey" PRIMARY KEY ("Id"),
    CONSTRAINT "SessionTrustedDevices_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX "SessionTrustedDevices_TokenHash_idx" ON "SessionTrustedDevices" USING btree ("TokenHash");
CREATE INDEX "SessionTrustedDevices_UserId_idx" ON "SessionTrustedDevices" USING btree ("UserId", "RevokedAt");

COMMIT;
