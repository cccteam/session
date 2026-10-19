-- Upgrade of a legacy Azure (oidc set) group to the Auth schema, step 1 of 4: the users
-- table, the same as the base set's. Apply the whole set at the cutover to Auth; the
-- legacy OIDCAzure type does not serve the group afterwards.
CREATE TABLE SessionUsers (
  Id                 STRING(36) NOT NULL,
  Username           STRING(MAX) NOT NULL,
  NormalizedUsername STRING(MAX) AS (NORMALIZE_AND_CASEFOLD(Username)) STORED,
  PasswordHash       STRING(MAX),
  Disabled           BOOL NOT NULL DEFAULT (FALSE),
  -- An operator set the password (a first password, a reset): the user changes it
  -- before anything else is served.
  PasswordChangeRequired BOOL NOT NULL DEFAULT (FALSE),
  -- The database's time at the insert and at the latest sign-in (null before the
  -- first); the driver writes both as commit timestamps.
  CreatedAt          TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp = true),
  LastSignInAt       TIMESTAMP OPTIONS (allow_commit_timestamp = true),
  CONSTRAINT CK_SessionUsersId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
) PRIMARY KEY(Id);

CREATE UNIQUE INDEX SessionUsersByNormalizedUsername ON SessionUsers(NormalizedUsername);
