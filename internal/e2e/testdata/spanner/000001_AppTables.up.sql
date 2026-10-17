-- The application's own tables for the Auth scenarios: the rows its hooks write in the
-- sign-in transactions, which the scenarios read afterwards. PartnerMembers has no foreign
-- key to SessionUsers: the user a sign-in provisions is a mutation buffered until the
-- commit, and a DML insert referencing it would be checked before then.
CREATE TABLE PartnerMembers (
    UserId  STRING(36) NOT NULL,
    Partner STRING(MAX) NOT NULL,
) PRIMARY KEY (UserId);

CREATE TABLE SignInAttempts (
    Subject STRING(MAX) NOT NULL,
    Outcome STRING(MAX) NOT NULL,
) PRIMARY KEY (Subject);
