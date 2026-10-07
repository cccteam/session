-- Accounts schema for Auth sessions (multi-method sessions, v0.13.0).
-- Applies on top of the base migrations set (Sessions, SessionUsers).

ALTER TABLE Sessions ADD COLUMN UserId STRING(36);
ALTER TABLE Sessions ADD COLUMN AuthenticatedAt TIMESTAMP;

CREATE INDEX SessionsByUserId ON Sessions(UserId);

CREATE TABLE SessionIdentities (
    Id          STRING(36) NOT NULL,
    UserId      STRING(36) NOT NULL,
    Method      STRING(32) NOT NULL,
    Connection  STRING(MAX) NOT NULL,
    Subject     STRING(MAX) NOT NULL,
    Tenant      STRING(MAX),
    EmailAtLink STRING(MAX),
    CreatedAt   TIMESTAMP NOT NULL,
    LastUsedAt  TIMESTAMP NOT NULL,
    CONSTRAINT CK_SessionIdentitiesId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT FK_SessionIdentities_SessionUsers FOREIGN KEY (UserId) REFERENCES SessionUsers (Id),
) PRIMARY KEY (Id);

CREATE UNIQUE INDEX SessionIdentitiesByKey ON SessionIdentities(Method, Connection, Subject);
CREATE INDEX SessionIdentitiesByUserId ON SessionIdentities(UserId);

-- Not interleaved: an interleaved child's key must begin with the parent's key column
-- (Id), so the events reference their session through a cascading foreign key instead.
CREATE TABLE SessionAuthEvents (
    SessionId  STRING(36) NOT NULL,
    Seq        INT64 NOT NULL,
    Method     STRING(32) NOT NULL,
    Connection STRING(MAX),
    IdpAmr     ARRAY<STRING(MAX)>,
    OccurredAt TIMESTAMP NOT NULL,
    CONSTRAINT FK_SessionAuthEvents_Sessions FOREIGN KEY (SessionId) REFERENCES Sessions (Id) ON DELETE CASCADE,
) PRIMARY KEY (SessionId, Seq);
