-- Tokens: the bearer credentials of the machine outlets. A row is one credential: an
-- application token a person issued to an application of their own, or the access or
-- refresh token of a device grant a command-line client obtained; the client holds an
-- opaque secret and the row keeps its hash. A token acts as its user (UserId) on the one
-- machine outlet it was issued for (Outlet) and is live while it is not revoked and not
-- expired. A device grant's tokens share a Family, and every successor a refresh
-- exchange issues joins it, so a rotated refresh token presented again revokes the
-- family at once (RevokedReason 'reuse'). CreatedAt, LastUsedAt and RevokedAt take the
-- commit time; ExpiresAt is the library's deadline, written as given.
CREATE TABLE SessionTokens (
    Id            STRING(36) NOT NULL,
    TokenHash     BYTES(32) NOT NULL,
    Kind          STRING(16) NOT NULL,
    UserId        STRING(36) NOT NULL,
    Outlet        STRING(MAX) NOT NULL,
    Name          STRING(MAX),
    Family        STRING(36),
    ClientId      STRING(MAX),
    CreatedAt     TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp = true),
    ExpiresAt     TIMESTAMP NOT NULL,
    LastUsedAt    TIMESTAMP OPTIONS (allow_commit_timestamp = true),
    RevokedAt     TIMESTAMP OPTIONS (allow_commit_timestamp = true),
    RevokedReason STRING(16),
    CONSTRAINT CK_SessionTokensId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT CK_SessionTokensKind CHECK (Kind IN ('application', 'access', 'refresh')),
    CONSTRAINT CK_SessionTokensRevokedReason CHECK (RevokedReason IS NULL OR RevokedReason IN ('revoked', 'rotated', 'reuse', 'user')),
    CONSTRAINT FK_SessionTokens_SessionUsers FOREIGN KEY (UserId) REFERENCES SessionUsers (Id) ON DELETE CASCADE,
) PRIMARY KEY (Id);

CREATE UNIQUE INDEX SessionTokensByTokenHash ON SessionTokens(TokenHash);
CREATE INDEX SessionTokensByUser ON SessionTokens(UserId, RevokedAt, ExpiresAt);
CREATE INDEX SessionTokensByFamily ON SessionTokens(Family, RevokedAt);

-- Device codes: the device authorizations command-line clients start (RFC 8628). The
-- client holds the opaque device code and the row keeps its hash; the person is shown
-- the user code, normalized here. A row is pending until a signed-in person approves
-- it (ApprovedAt, UserId) or denies it (DeniedAt), or it expires; an approved row is
-- consumed once (ConsumedAt), when the client's poll redeems it for its tokens.
-- LastPolledAt holds the client to the polling interval. The time columns but
-- ExpiresAt take the commit time.
CREATE TABLE SessionDeviceCodes (
    Id             STRING(36) NOT NULL,
    DeviceCodeHash BYTES(32) NOT NULL,
    UserCode       STRING(16) NOT NULL,
    ClientId       STRING(MAX) NOT NULL,
    Outlet         STRING(MAX) NOT NULL,
    UserId         STRING(36),
    CreatedAt      TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp = true),
    ExpiresAt      TIMESTAMP NOT NULL,
    ApprovedAt     TIMESTAMP OPTIONS (allow_commit_timestamp = true),
    DeniedAt       TIMESTAMP OPTIONS (allow_commit_timestamp = true),
    LastPolledAt   TIMESTAMP OPTIONS (allow_commit_timestamp = true),
    ConsumedAt     TIMESTAMP OPTIONS (allow_commit_timestamp = true),
    CONSTRAINT CK_SessionDeviceCodesId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT FK_SessionDeviceCodes_SessionUsers FOREIGN KEY (UserId) REFERENCES SessionUsers (Id) ON DELETE CASCADE,
) PRIMARY KEY (Id);

CREATE UNIQUE INDEX SessionDeviceCodesByHash ON SessionDeviceCodes(DeviceCodeHash);
CREATE INDEX SessionDeviceCodesByUserCode ON SessionDeviceCodes(UserCode, ExpiresAt);
