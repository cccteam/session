BEGIN;

CREATE TABLE "OIDCUserData"
(
    "UserId" UUID NOT NULL,
    "Email" character varying,
    "DisplayName" character varying,
    "Theme" character varying,
    CONSTRAINT "OIDCUserData_pkey" PRIMARY KEY ("UserId"),
    CONSTRAINT "OIDCUserData_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "OIDCUsers"("Id") ON DELETE CASCADE
);

CREATE TABLE "SessionCustomData"
(
    "SessionId" UUID NOT NULL,
    "UserIdRef" character varying,
    CONSTRAINT "SessionCustomData_pkey" PRIMARY KEY ("SessionId"),
    CONSTRAINT "SessionCustomData_SessionId_fkey" FOREIGN KEY ("SessionId") REFERENCES "Sessions"("Id") ON DELETE CASCADE
);

COMMIT;
