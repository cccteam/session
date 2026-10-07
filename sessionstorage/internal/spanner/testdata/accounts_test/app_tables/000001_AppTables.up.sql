-- Test-only application tables for the accounts conformance suite: the rows an
-- application's own hooks write in the sign-in transactions, and a custom session data
-- table for drivertest.CustomStringData.
CREATE TABLE HookRecords (
    RecordKey   STRING(MAX) NOT NULL,
    RecordValue STRING(MAX) NOT NULL,
) PRIMARY KEY (RecordKey);

CREATE TABLE SessionCustomData (
    SessionId    STRING(36) NOT NULL,
    CustomString STRING(MAX),
    CONSTRAINT FK_SessionCustomData_Sessions FOREIGN KEY (SessionId) REFERENCES Sessions (Id) ON DELETE CASCADE,
) PRIMARY KEY (SessionId);
