CREATE TABLE Sessions
(
    Id STRING(36) NOT NULL,
    OidcSid STRING(MAX) NOT NULL,
    Username STRING(MAX) NOT NULL,
    CreatedAt TIMESTAMP NOT NULL,
    UpdatedAt TIMESTAMP NOT NULL,
    Expired BOOL NOT NULL,
    CONSTRAINT CK_SessionsId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
) PRIMARY KEY (Id), ROW DELETION POLICY (OLDER_THAN(CreatedAt, INTERVAL 30 DAY));

CREATE INDEX SessionsByOidcSid ON Sessions(OidcSid DESC);
CREATE INDEX SessionsByUsername ON Sessions(Username);
CREATE INDEX SessionsByExpired ON Sessions(Expired DESC);