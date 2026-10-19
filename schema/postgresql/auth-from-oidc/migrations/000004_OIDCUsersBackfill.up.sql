-- Step 4 of 4: the OIDC user anchor's rows become users and Azure identities under the
-- same ids, so a custom user data table keyed by the anchor's ids keeps its rows (retarget
-- its foreign key to SessionUsers). Live sessions take their user by username. A group
-- that never enabled the anchor has an empty OIDCUsers table, or none: drop the last
-- three statements then. Two anchor rows with usernames that casefold alike stop the
-- backfill: resolve them first. The anchor table is not dropped here; drop it in the
-- release after the cutover, once nothing can roll back to the legacy type.
BEGIN;

INSERT INTO "SessionUsers" ("Id", "Username")
    SELECT "Id", "Username" FROM "OIDCUsers";

INSERT INTO "SessionIdentities" ("Id", "UserId", "Method", "Connection", "Subject", "Tenant", "EmailAtLink", "CreatedAt", "LastUsedAt")
    SELECT gen_random_uuid(), "Id", 'azure', "Tid", "Oid", NULL, NULL, "CreatedAt", "UpdatedAt" FROM "OIDCUsers";

UPDATE "Sessions" s SET "UserId" = u."Id"
    FROM "SessionUsers" u
    WHERE s."UserId" IS NULL AND s."Username" = u."Username";

COMMIT;
