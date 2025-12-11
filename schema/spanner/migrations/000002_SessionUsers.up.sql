CREATE TABLE SessionUsers (
  Id            STRING(36) NOT NULL,
  Username      STRING(MAX) NOT NULL,
  PasswordHash  STRING(MAX),
  Disabled      BOOL NOT NULL DEFAULT (FALSE),
  CONSTRAINT CK_SessionUsersId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
) PRIMARY KEY(Id);

CREATE UNIQUE INDEX SessionUsersByUsername ON SessionUsers(Username);