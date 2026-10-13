-- The application's own tables for the Auth scenarios: the rows its hooks write in the
-- sign-in transactions, which the scenarios read afterwards.
BEGIN;

CREATE TABLE "PartnerMembers"
(
    "UserId" UUID NOT NULL,
    "Partner" character varying NOT NULL,
    CONSTRAINT "PartnerMembers_pkey" PRIMARY KEY ("UserId"),
    CONSTRAINT "PartnerMembers_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id")
);

CREATE TABLE "SignInAttempts"
(
    "Subject" character varying NOT NULL,
    "Outcome" character varying NOT NULL,
    CONSTRAINT "SignInAttempts_pkey" PRIMARY KEY ("Subject")
);

COMMIT;
