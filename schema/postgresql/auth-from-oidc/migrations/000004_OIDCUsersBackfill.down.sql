BEGIN;
UPDATE "Sessions" SET "UserId" = NULL;
DELETE FROM "SessionIdentities" WHERE "Method" = 'azure' AND "UserId" IN (SELECT "Id" FROM "OIDCUsers");
DELETE FROM "SessionUsers" WHERE "Id" IN (SELECT "Id" FROM "OIDCUsers");
COMMIT;
