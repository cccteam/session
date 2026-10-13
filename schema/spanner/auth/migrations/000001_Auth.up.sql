-- Auth schema for Auth sessions (multi-method sessions, v0.13.0).
-- Applies on top of the base migrations set (Sessions, SessionUsers). An application
-- whose tables are named per auth group applies it under its own names.
--
-- A session belongs to a user (UserId, null only for a role-principal impersonation),
-- and deleting the user deletes its sessions, their auth events and its identity links.
-- ProviderSessionId is the identity provider's session id when the method reports one,
-- for front-channel logout; it is nullable on every Auth sessions table so that a
-- method added later needs no DDL.

ALTER TABLE Sessions ADD COLUMN UserId STRING(36);
ALTER TABLE Sessions ADD COLUMN AuthenticatedAt TIMESTAMP;
ALTER TABLE Sessions ADD COLUMN ProviderSessionId STRING(MAX);
ALTER TABLE Sessions ADD CONSTRAINT FK_Sessions_SessionUsers FOREIGN KEY (UserId) REFERENCES SessionUsers (Id) ON DELETE CASCADE;

CREATE INDEX SessionsByUserId ON Sessions(UserId);
CREATE INDEX SessionsByProviderSessionId ON Sessions(ProviderSessionId);

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

-- Not interleaved: an interleaved child's key must begin with the parent's key column
-- (Id), so the events reference their session through a cascading foreign key instead.
CREATE TABLE SessionAuthEvents (
    SessionId  STRING(36) NOT NULL,
    Seq        INT64 NOT NULL,
    Method     STRING(MAX) NOT NULL,
    Connection STRING(MAX),
    IdpAmr     ARRAY<STRING(MAX)>,
    OccurredAt TIMESTAMP NOT NULL,
    CONSTRAINT FK_SessionAuthEvents_Sessions FOREIGN KEY (SessionId) REFERENCES Sessions (Id) ON DELETE CASCADE,
) PRIMARY KEY (SessionId, Seq);
