-- Table: Sessions

-- DROP TABLE IF EXISTS Sessions;

CREATE TABLE IF NOT EXISTS Sessions
(
    Id STRING(36) NOT NULL,
    OidcSid STRING(36) NOT NULL,
    Username STRING(MAX) NOT NULL,
    CreatedAt TIMESTAMP NOT NULL,
    UpdatedAt TIMESTAMP NOT NULL,
    Expired BOOL NOT NULL,
    CONSTRAINT CK_SessionsId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT CK_SessionsOidcSid CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
) PRIMARY KEY (Id);

-- DROP INDEX IF EXISTS Sessions_OidcSid_idx;

CREATE INDEX IF NOT EXISTS Sessions_OidcSid_idx
    ON Sessions
    (OidcSid DESC);

-- DROP INDEX IF EXISTS Sessions_Expired_idx;

CREATE INDEX IF NOT EXISTS Sessions_Expired_idx
    ON Sessions
    (Expired DESC);