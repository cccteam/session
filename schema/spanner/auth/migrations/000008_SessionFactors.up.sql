-- Factor codes and trusted devices: the second factor the library runs. A factor code
-- is one code mailed for a pending sign-in (PendingId): the mail carries the code and
-- the row keeps its hash; the row is live while it is not consumed and not expired,
-- Attempts counts the wrong codes entered against it, and a new code for the same
-- pending sign-in consumes the earlier one. A trusted device is a browser the person
-- asked to be remembered after a second factor (UserId): the browser holds an opaque
-- token in a cookie and the row keeps its hash; it stands in for the factor while it is
-- not revoked and not expired. A code goes with its pending sign-in and a device with
-- its user. CreatedAt, ConsumedAt, LastUsedAt and RevokedAt take the commit time;
-- ExpiresAt is the library's deadline, written as given.
CREATE TABLE SessionFactorCodes (
    Id         STRING(36) NOT NULL,
    PendingId  STRING(36) NOT NULL,
    Email      STRING(MAX) NOT NULL,
    CodeHash   BYTES(32) NOT NULL,
    Attempts   INT64 NOT NULL,
    CreatedAt  TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp = true),
    ExpiresAt  TIMESTAMP NOT NULL,
    ConsumedAt TIMESTAMP OPTIONS (allow_commit_timestamp = true),
    CONSTRAINT CK_SessionFactorCodesId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT FK_SessionFactorCodes_SessionPendingSignIns FOREIGN KEY (PendingId) REFERENCES SessionPendingSignIns (Id) ON DELETE CASCADE,
) PRIMARY KEY (Id);

CREATE INDEX SessionFactorCodesByPending ON SessionFactorCodes(PendingId, ConsumedAt, ExpiresAt);

CREATE TABLE SessionTrustedDevices (
    Id         STRING(36) NOT NULL,
    UserId     STRING(36) NOT NULL,
    TokenHash  BYTES(32) NOT NULL,
    CreatedAt  TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp = true),
    ExpiresAt  TIMESTAMP NOT NULL,
    LastUsedAt TIMESTAMP OPTIONS (allow_commit_timestamp = true),
    RevokedAt  TIMESTAMP OPTIONS (allow_commit_timestamp = true),
    CONSTRAINT CK_SessionTrustedDevicesId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT FK_SessionTrustedDevices_SessionUsers FOREIGN KEY (UserId) REFERENCES SessionUsers (Id) ON DELETE CASCADE,
) PRIMARY KEY (Id);

CREATE UNIQUE INDEX SessionTrustedDevicesByTokenHash ON SessionTrustedDevices(TokenHash);
CREATE INDEX SessionTrustedDevicesByUser ON SessionTrustedDevices(UserId, RevokedAt);
