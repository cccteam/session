-- Table: Sessions

-- DROP TABLE Sessions;

CREATE TABLE Sessions
(
    Id STRING(36) NOT NULL,
    OidcSid STRING(MAX) NOT NULL,
    Username STRING(MAX) NOT NULL,
    CreatedAt TIMESTAMP NOT NULL,
    UpdatedAt TIMESTAMP NOT NULL,
    Expired BOOL NOT NULL,
    CONSTRAINT CK_SessionsId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
) PRIMARY KEY (Id);

-- DROP INDEX Sessions_OidcSid_idx;

CREATE INDEX Sessions_OidcSid_idx
    ON Sessions
    (OidcSid DESC);

-- DROP INDEX Sessions_Expired_idx;

CREATE INDEX Sessions_Expired_idx
    ON Sessions
    (Expired DESC);