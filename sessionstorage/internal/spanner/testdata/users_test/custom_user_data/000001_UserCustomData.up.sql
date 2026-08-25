CREATE TABLE UserCustomData (
    UserId     STRING(36) NOT NULL,
    Locale     STRING(MAX),
    Theme      STRING(MAX),
    LoginCount INT64,
    CONSTRAINT CK_UserCustomDataUserId CHECK (REGEXP_CONTAINS(UserId, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT FK_UserCustomData_SessionUsers FOREIGN KEY (UserId) REFERENCES SessionUsers(Id) ON DELETE CASCADE,
) PRIMARY KEY (UserId);
