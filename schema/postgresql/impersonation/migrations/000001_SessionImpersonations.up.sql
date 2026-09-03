BEGIN;

-- Table: SessionImpersonations
--
-- The impersonation record is evidence: it deliberately carries NO foreign key to
-- the session table, so it outlives the session row. Retention is the
-- application's policy.

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
    "StartedAt" timestamp without time zone NOT NULL,
    "ExpiresAt" timestamp without time zone NOT NULL,
    "EndedAt" timestamp without time zone,
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
