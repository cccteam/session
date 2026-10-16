-- Step 2 of 4: the Auth columns and tables, as the auth set creates them, on the
-- legacy Azure sessions table. OidcSid gives way to ProviderSessionId, nullable: Auth
-- records the provider's session id when the method reports one, with its issuer in
-- ProviderSessionIssuer. Spanner cannot rename a column, so the legacy column is
-- dropped: the live legacy sessions lose their id, and a later Entra logout cannot
-- reach them until the person signs in again, which the upgrade expects anyway.
DROP INDEX SessionsByOidcSid;
ALTER TABLE Sessions DROP COLUMN OidcSid;
ALTER TABLE Sessions ADD COLUMN ProviderSessionId STRING(MAX);
ALTER TABLE Sessions ADD COLUMN ProviderSessionIssuer STRING(MAX);
CREATE INDEX SessionsByProviderSessionId ON Sessions(ProviderSessionId);

ALTER TABLE Sessions ADD COLUMN UserId STRING(36);
ALTER TABLE Sessions ADD COLUMN AuthenticatedAt TIMESTAMP;
ALTER TABLE Sessions ADD CONSTRAINT FK_Sessions_SessionUsers FOREIGN KEY (UserId) REFERENCES SessionUsers (Id) ON DELETE CASCADE;

CREATE INDEX SessionsByUserId ON Sessions(UserId);

CREATE TABLE SessionIdentities (
    Id          STRING(36) NOT NULL,
    UserId      STRING(36) NOT NULL,
    Method      STRING(MAX) NOT NULL,
    Connection  STRING(MAX) NOT NULL,
    Subject     STRING(MAX) NOT NULL,
    Tenant      STRING(MAX),
    EmailAtLink STRING(MAX),
    CreatedAt   TIMESTAMP NOT NULL,
    LastUsedAt  TIMESTAMP NOT NULL,
    CONSTRAINT CK_SessionIdentitiesId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT FK_SessionIdentities_SessionUsers FOREIGN KEY (UserId) REFERENCES SessionUsers (Id) ON DELETE CASCADE,
) PRIMARY KEY (Id);

CREATE UNIQUE INDEX SessionIdentitiesByKey ON SessionIdentities(Method, Connection, Subject);
CREATE INDEX SessionIdentitiesByUserId ON SessionIdentities(UserId);

CREATE TABLE SessionAuthEvents (
    SessionId  STRING(36) NOT NULL,
    Seq        INT64 NOT NULL,
    Method     STRING(MAX) NOT NULL,
    Connection STRING(MAX),
    IdpAmr     ARRAY<STRING(MAX)>,
    OccurredAt TIMESTAMP NOT NULL,
    CONSTRAINT FK_SessionAuthEvents_Sessions FOREIGN KEY (SessionId) REFERENCES Sessions (Id) ON DELETE CASCADE,
) PRIMARY KEY (SessionId, Seq);
