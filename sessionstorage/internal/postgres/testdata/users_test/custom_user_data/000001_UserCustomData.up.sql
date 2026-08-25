BEGIN;

CREATE TABLE "UserCustomData"
(
    "UserId" UUID NOT NULL,
    "Locale" character varying,
    "Theme" character varying,
    "LoginCount" integer,
    CONSTRAINT "UserCustomData_pkey" PRIMARY KEY ("UserId"),
    CONSTRAINT "UserCustomData_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers"("Id") ON DELETE CASCADE
);

COMMIT;
