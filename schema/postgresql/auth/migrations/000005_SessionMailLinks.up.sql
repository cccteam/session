-- Mail links: the single-use links the library mails. A row is one link: an invitation
-- to an address, carrying the tenant and the roles its acceptance grants and who sent
-- it; the verification of an address a signed-in person adds (UserId names the account,
-- Email the address); or a sign-up a person starts by giving their address. The mail
-- carries an opaque token and the row keeps its hash; the row is accepted only while it
-- is live, not expired and not consumed, and is consumed by a conditional update so one
-- link completes once. A revoked invitation is consumed by hand. A verification link
-- goes with its user. CreatedAt and ConsumedAt take the transaction's time; ExpiresAt
-- is the library's deadline, written as given.
BEGIN;

CREATE TABLE "SessionMailLinks"
(
    "Id" UUID NOT NULL,
    "TokenHash" bytea NOT NULL,
    "Kind" character varying(16) NOT NULL,
    "Email" character varying NOT NULL,
    "UserId" UUID,
    "Tenant" character varying,
    "RoleNames" character varying[],
    "InvitedBy" UUID,
    "CreatedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "ConsumedAt" timestamp with time zone,
    CONSTRAINT "SessionMailLinks_pkey" PRIMARY KEY ("Id"),
    CONSTRAINT "SessionMailLinks_Kind_check" CHECK ("Kind" IN ('invitation', 'verification', 'sign-up')),
    CONSTRAINT "SessionMailLinks_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX "SessionMailLinks_TokenHash_idx" ON "SessionMailLinks" USING btree ("TokenHash");
CREATE INDEX "SessionMailLinks_Kind_idx" ON "SessionMailLinks" USING btree ("Kind", "ConsumedAt", "ExpiresAt");

COMMIT;
