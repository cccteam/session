-- Pending sign-ins: a sign-in that waits for a password confirmation or the
-- application's MFA step, held server-side. The browser's pending cookie carries only an
-- opaque token; TokenHash is its SHA-256. A row is live until ExpiresAt or until a
-- completion, cancellation or replacement consumes it (ConsumedAt), once.
CREATE TABLE SessionPendingSignIns (
    Id            STRING(36) NOT NULL,
    TokenHash     BYTES(32) NOT NULL,
    Step          STRING(16) NOT NULL,
    Registration  STRING(MAX) NOT NULL,
    Method        STRING(MAX) NOT NULL,
    Connection    STRING(MAX) NOT NULL,
    Subject       STRING(MAX) NOT NULL,
    Email         STRING(MAX) NOT NULL,
    EmailVerified BOOL NOT NULL,
    IdpAmr        ARRAY<STRING(MAX)>,
    Claims        BYTES(MAX),
    SignInName    STRING(MAX) NOT NULL,
    Guest         BOOL NOT NULL,
    Organization  STRING(MAX) NOT NULL,
    UserId        STRING(36),
    Username      STRING(MAX) NOT NULL,
    Tenant        STRING(MAX) NOT NULL,
    Events        BYTES(MAX) NOT NULL,
    RoleNames     ARRAY<STRING(MAX)>,
    Factors       ARRAY<STRING(MAX)>,
    ReturnUrl     STRING(MAX) NOT NULL,
    ProviderSessionId STRING(MAX),
    ProviderSessionIssuer STRING(MAX),
    CreatedAt     TIMESTAMP NOT NULL,
    ExpiresAt     TIMESTAMP NOT NULL,
    ConsumedAt    TIMESTAMP,
    CONSTRAINT CK_SessionPendingSignInsId CHECK (REGEXP_CONTAINS(Id, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT CK_SessionPendingSignInsStep CHECK (Step IN ('confirmation', 'mfa')),
) PRIMARY KEY (Id);

CREATE UNIQUE INDEX SessionPendingSignInsByTokenHash ON SessionPendingSignIns(TokenHash);
CREATE INDEX SessionPendingSignInsByExpiresAt ON SessionPendingSignIns(ExpiresAt);
