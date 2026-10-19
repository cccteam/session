-- The application's custom session and user data tables: the session's row is resolved
-- in the sign-in's transaction; the user's row is written with the user.
BEGIN;

CREATE TABLE "SessionCustomData"
(
    "SessionId" UUID NOT NULL,
    "Partner" character varying NOT NULL,
    CONSTRAINT "SessionCustomData_pkey" PRIMARY KEY ("SessionId"),
    CONSTRAINT "SessionCustomData_SessionId_fkey" FOREIGN KEY ("SessionId") REFERENCES "Sessions" ("Id") ON DELETE CASCADE
);

CREATE TABLE "UserCustomData"
(
    "UserId" UUID NOT NULL,
    "Locale" character varying NOT NULL,
    CONSTRAINT "UserCustomData_pkey" PRIMARY KEY ("UserId"),
    CONSTRAINT "UserCustomData_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id") ON DELETE CASCADE
);

COMMIT;
