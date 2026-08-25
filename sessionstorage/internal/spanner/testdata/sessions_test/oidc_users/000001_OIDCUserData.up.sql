CREATE TABLE OIDCUserData (
    UserId      STRING(36) NOT NULL,
    Email       STRING(MAX),
    DisplayName STRING(MAX),
    Theme       STRING(MAX),
    CONSTRAINT CK_OIDCUserDataUserId CHECK (REGEXP_CONTAINS(UserId, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT FK_OIDCUserData_OIDCUsers FOREIGN KEY (UserId) REFERENCES OIDCUsers(Id) ON DELETE CASCADE,
) PRIMARY KEY (UserId);

CREATE TABLE SessionCustomData (
    SessionId STRING(36) NOT NULL,
    UserIdRef STRING(36),
    CONSTRAINT FK_SessionCustomData_Sessions FOREIGN KEY (SessionId) REFERENCES Sessions(Id) ON DELETE CASCADE,
) PRIMARY KEY (SessionId);
