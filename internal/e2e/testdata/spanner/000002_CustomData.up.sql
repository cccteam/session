-- The application's custom session and user data tables: the session's row is resolved
-- in the sign-in's transaction; the user's row is written with the user. Both are
-- written by the library as mutations in the transaction that inserts their parent, so
-- the foreign keys hold at the commit.
CREATE TABLE SessionCustomData (
    SessionId STRING(36) NOT NULL,
    Partner   STRING(MAX) NOT NULL,
    CONSTRAINT FK_SessionCustomData_Sessions FOREIGN KEY (SessionId) REFERENCES Sessions(Id) ON DELETE CASCADE,
) PRIMARY KEY (SessionId);

CREATE TABLE UserCustomData (
    UserId STRING(36) NOT NULL,
    Locale STRING(MAX) NOT NULL,
    CONSTRAINT FK_UserCustomData_SessionUsers FOREIGN KEY (UserId) REFERENCES SessionUsers(Id) ON DELETE CASCADE,
) PRIMARY KEY (UserId);
