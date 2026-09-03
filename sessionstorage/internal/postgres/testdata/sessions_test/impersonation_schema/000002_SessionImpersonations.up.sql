BEGIN;

CREATE TABLE "SessionImpersonations"
(
    "SessionId" UUID NOT NULL,
    "ActorUsername" character varying NOT NULL,
    "ActorRealm" character varying,
    "SourceSessionId" UUID,
    "PrincipalKind" character varying(16) NOT NULL,
    "PrincipalUser" character varying,
    "PrincipalRole" character varying,
    "Mask" character varying,
    "Reason" character varying,
    "StartedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "EndedAt" timestamp with time zone,
    "EndReason" character varying(16),
    CONSTRAINT "SessionImpersonations_pkey" PRIMARY KEY ("SessionId"),
    CONSTRAINT "SessionImpersonations_PrincipalKind_check" CHECK ("PrincipalKind" IN ('User', 'Role'))
);

CREATE INDEX "SessionImpersonations_ActorUsername_idx"
    ON "SessionImpersonations" USING btree
    ("ActorUsername" ASC, "StartedAt" DESC);

CREATE INDEX "SessionImpersonations_PrincipalUser_idx"
    ON "SessionImpersonations" USING btree
    ("PrincipalUser" ASC, "StartedAt" DESC);

COMMIT;
