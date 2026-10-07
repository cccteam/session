-- Test-only application tables for the accounts conformance suite: the rows an
-- application's own hooks write in the sign-in transactions, and a custom session data
-- table for drivertest.CustomStringData.
BEGIN;

CREATE TABLE "HookRecords"
(
    "RecordKey" character varying NOT NULL,
    "RecordValue" character varying NOT NULL,
    CONSTRAINT "HookRecords_pkey" PRIMARY KEY ("RecordKey")
);

CREATE TABLE "SessionCustomData"
(
    "SessionId" UUID NOT NULL,
    "CustomString" character varying,
    CONSTRAINT "SessionCustomData_pkey" PRIMARY KEY ("SessionId"),
    CONSTRAINT "SessionCustomData_SessionId_fkey" FOREIGN KEY ("SessionId") REFERENCES "Sessions" ("Id") ON DELETE CASCADE
);

COMMIT;
