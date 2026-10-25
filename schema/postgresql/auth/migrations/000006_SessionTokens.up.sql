-- Tokens: the bearer credentials of the machine outlets. A row is one credential: an
-- application token a person issued to an application of their own, or the access or
-- refresh token of a device grant a command-line client obtained; the client holds an
-- opaque secret and the row keeps its hash. A token acts as its user (UserId) on the one
-- machine outlet it was issued for (Outlet) and is live while it is not revoked and not
-- expired. A device grant's tokens share a Family, and every successor a refresh
-- exchange issues joins it, so a rotated refresh token presented again revokes the
-- family at once (RevokedReason 'reuse'). CreatedAt, LastUsedAt and RevokedAt take the
-- transaction's time; ExpiresAt is the library's deadline, written as given.
BEGIN;

CREATE TABLE "SessionTokens"
(
    "Id" UUID NOT NULL,
    "TokenHash" bytea NOT NULL,
    "Kind" character varying(16) NOT NULL,
    "UserId" UUID NOT NULL,
    "Outlet" character varying NOT NULL,
    "Name" character varying,
    "Family" UUID,
    "ClientId" character varying,
    "CreatedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "LastUsedAt" timestamp with time zone,
    "RevokedAt" timestamp with time zone,
    "RevokedReason" character varying(16),
    CONSTRAINT "SessionTokens_pkey" PRIMARY KEY ("Id"),
    CONSTRAINT "SessionTokens_Kind_check" CHECK ("Kind" IN ('application', 'access', 'refresh')),
    CONSTRAINT "SessionTokens_RevokedReason_check" CHECK ("RevokedReason" IS NULL OR "RevokedReason" IN ('revoked', 'rotated', 'reuse', 'user')),
    CONSTRAINT "SessionTokens_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX "SessionTokens_TokenHash_idx" ON "SessionTokens" USING btree ("TokenHash");
CREATE INDEX "SessionTokens_UserId_idx" ON "SessionTokens" USING btree ("UserId", "RevokedAt", "ExpiresAt");
CREATE INDEX "SessionTokens_Family_idx" ON "SessionTokens" USING btree ("Family", "RevokedAt");

-- Device codes: the device authorizations command-line clients start (RFC 8628). The
-- client holds the opaque device code and the row keeps its hash; the person is shown
-- the user code, normalized here. A row is pending until a signed-in person approves
-- it (ApprovedAt, UserId) or denies it (DeniedAt), or it expires; an approved row is
-- consumed once (ConsumedAt), when the client's poll redeems it for its tokens.
-- LastPolledAt holds the client to the polling interval. The time columns but
-- ExpiresAt take the transaction's time.
CREATE TABLE "SessionDeviceCodes"
(
    "Id" UUID NOT NULL,
    "DeviceCodeHash" bytea NOT NULL,
    "UserCode" character varying(16) NOT NULL,
    "ClientId" character varying NOT NULL,
    "Outlet" character varying NOT NULL,
    "UserId" UUID,
    "CreatedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "ApprovedAt" timestamp with time zone,
    "DeniedAt" timestamp with time zone,
    "LastPolledAt" timestamp with time zone,
    "ConsumedAt" timestamp with time zone,
    CONSTRAINT "SessionDeviceCodes_pkey" PRIMARY KEY ("Id"),
    CONSTRAINT "SessionDeviceCodes_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX "SessionDeviceCodes_DeviceCodeHash_idx" ON "SessionDeviceCodes" USING btree ("DeviceCodeHash");
CREATE INDEX "SessionDeviceCodes_UserCode_idx" ON "SessionDeviceCodes" USING btree ("UserCode", "ExpiresAt");

COMMIT;
