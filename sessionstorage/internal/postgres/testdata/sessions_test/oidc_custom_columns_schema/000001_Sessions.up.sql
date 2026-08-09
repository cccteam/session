BEGIN;

CREATE TABLE "Sessions"
(
    "Id" UUID NOT NULL,
    "OidcSid" character varying NOT NULL,
    "Username" character varying NOT NULL,
    "CreatedAt" timestamp without time zone NOT NULL,
    "UpdatedAt" timestamp without time zone NOT NULL,
    "Expired" boolean NOT NULL,
    CONSTRAINT "Sessions_pkey" PRIMARY KEY ("Id")
);

CREATE INDEX "Sessions_OidcSid_idx"
    ON "Sessions" USING btree
    ("OidcSid" ASC NULLS LAST);

CREATE TABLE "SessionCustomData"
(
    "SessionId" UUID NOT NULL,
    "CustomString" character varying,
    "CustomInt" integer,
    CONSTRAINT "SessionCustomData_pkey" PRIMARY KEY ("SessionId"),
    CONSTRAINT "SessionCustomData_SessionId_fkey" FOREIGN KEY ("SessionId") REFERENCES "Sessions"("Id") ON DELETE CASCADE
);

COMMIT;
