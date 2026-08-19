---
name: session-package
description: >-
  How to use github.com/cccteam/session — this repo's Go package for
  database-backed HTTP session management with encrypted cookies, XSRF
  protection, and three authentication flows (Azure OIDC, username/password,
  and preauth/bring-your-own-auth). Use this skill whenever working in or with
  this repo: wiring session middleware into an HTTP router, adding login/logout
  handlers, choosing between OIDCAzure, PasswordAuth, and Preauth, setting up
  Sessions/SessionUsers database tables in PostgreSQL or Spanner, reading the
  current user or session ID from a request context, configuring cookies or
  session timeouts, or debugging XSRF/authentication failures in a consuming
  service.
---

# The session package

`github.com/cccteam/session` manages user sessions for Go HTTP services:
creation, storage, expiration, and XSRF protection. Sessions are persisted in
a database (PostgreSQL or Google Cloud Spanner) and referenced from the
browser by a PASETO-encrypted cookie. See `README.md` for the feature
overview; this skill covers how the pieces fit together and how to wire them
up. The package docs in the source are authoritative — key files are called
out below.

## Architecture in one paragraph

You construct one of three top-level handler types — `OIDCAzure`
(`oidc_azure.go`), `PasswordAuth` (`password_auth.go`), or `Preauth`
(`preauth.go`) — around a storage implementation from the `sessionstorage`
subpackage. The handler type provides `http.Handler` middleware and
`http.HandlerFunc` endpoints you mount on your router. Each handler also
exposes an `API()` method returning a programmatic interface (e.g.
`PreauthAPI.Login`) for use outside the bundled HTTP handlers. Session and
user data land in your context via the `sessioninfo` subpackage.

## Choosing an authentication flow

- **`OIDCAzure`** — Azure OIDC Authorization Code Flow with PKCE. Users and
  roles are managed centrally in Active Directory; the login callback
  synchronizes roles from token claims. Read the `OIDCAzure` type comment in
  `oidc_azure.go` before choosing this: role sync is domain-blind (not
  multi-tenant-safe), removes any app-assigned role absent from the token,
  and rejects logins that yield no recognized role.
- **`PasswordAuth`** — username/password with user storage, Argon2 hashing
  (auto-upgrading legacy hashes), and full user management handlers
  (create/activate/deactivate/delete users, change username/password).
- **`Preauth`** — you authenticate the user however you like, then call
  `preauth.API().Login(ctx, w, username)` to establish the session. Use this
  when neither built-in flow fits.

## Setup steps

### 1. Database schema

Apply the migrations from `schema/<postgresql|spanner>/`:

- `migrations/` — `Sessions` table (all flows) and `SessionUsers` table
  (required for `PasswordAuth` only).
- `oidc/migrations/` — the OIDC variant of `Sessions` (adds an `OidcSid`
  column). Use these instead of the base `Sessions` migration for `OIDCAzure`.

Table names default to `Sessions` and `SessionUsers`; override with
`WithSessionTableName` / `WithUserTableName` options.

### 2. Storage

Pick the constructor from `sessionstorage` matching your flow and database:

| Flow | PostgreSQL | Spanner |
|---|---|---|
| OIDC | `NewPostgresOIDC(pg)` | `NewSpannerOIDC(client)` |
| Password | `NewPostgresPassword(pg)` | `NewSpannerPasswordAuth(client)` |
| Preauth | `NewPostgresPreauth(pg)` | `NewSpannerPreauth(client)` |

Postgres constructors take a `postgres.Queryer` (a pgx v5 `Begin`/`Query`/
`QueryRow`/`Exec` interface, satisfied by `*pgxpool.Pool`);
Spanner constructors take a `*spanner.Client`. Custom storage is possible by
implementing the `OIDCStore`, `PasswordAuthStore`, or `PreauthStore`
interfaces in `sessionstorage/sessionstorage_iface.go`.

### 3. Cookie key

Every constructor requires a `cookieKey`: a Base64-encoded string of at least
32 bytes of cryptographically secure random data (e.g.
`openssl rand -base64 32`). Treat it as a secret. Cookies are `Secure` by
default; build with the `insecurecookie` build tag only for local non-HTTPS
development (see `cookie/config_dev.go`).

### 4. Construct the handler

```go
// Preauth example
sess, err := session.NewPreauth(
    sessionstorage.NewPostgresPreauth(pool),
    cookieKey,
    session.WithSessionTimeout(30*time.Minute),
    session.WithCookieName("myapp-session"),
)

// OIDC example — see oidc_azure.go for role-sync caveats
sess, err := session.NewOIDCAzure(
    sessionstorage.NewPostgresOIDC(pool),
    userRoleManager, // your session.UserRoleManager, or session.DisableUserRoleManagement()
    cookieKey,
    issuerURL, clientID, clientSecret, redirectURL,
    session.WithLoginURL("/login"),
)
```

Options live in `options.go`: cookie names/domain (`WithCookieName`,
`WithCookieDomain`, `WithXSRFCookieName`, `WithXSRFHeaderName`), session
behavior (`WithSessionTimeout` — default 10m, `WithLogHandler`,
`WithSessionTableName`, `WithUserTableName`), OIDC (`WithLoginURL`), and
password auth (`AutoUpgradeHashes`, `HashAlgorithm`).

### 5. Wire the middleware — order matters

`StartSession` must run before everything else (it restores/creates the
session and puts the session ID in the context; `SetXSRFToken` and
`ValidateSession` both panic or fail without it):

```
StartSession → SetXSRFToken → ValidateXSRFToken → ValidateSession → your handlers
```

- `StartSession` — restore session from cookie or create a new one.
- `SetXSRFToken` — set/refresh the XSRF cookie (may redirect unsafe methods
  once to pick up the cookie).
- `ValidateXSRFToken` — reject unsafe methods (POST/PUT/…) lacking a valid
  XSRF header; clients must echo the XSRF cookie value in the XSRF header.
- `ValidateSession` — check the session in the database for expiration and
  bump last-activity. Mount this only on routes requiring authentication.

Endpoints to mount: `Authenticated()`, `Logout()`, plus per flow:
`OIDCAzure.Login()`, `CallbackOIDC()`, `FrontChannelLogout()`;
`PasswordAuth.Login()`, `CreateUser()`, `ChangeUserPassword()`,
`ChangeUsername()`, `ActivateUser()`, `DeactivateUser()`, `DeleteUser()`
(user-management routes take the user ID from the
`session.RouterSessionUserID` router param).

## Reading session data in your handlers

Use the `sessioninfo` subpackage downstream of the middleware:

- `sessioninfo.FromRequest(r)` / `FromCtx(ctx)` → `*SessionInfo` (ID,
  Username, timestamps, Expired) — available after `ValidateSession`.
- `sessioninfo.IDFromRequest(r)` / `IDFromCtx(ctx)` → session `ccc.UUID` —
  available after `StartSession`.
- `sessioninfo.UserFromRequest(r)` / `UserFromCtx(ctx)` → `*UserInfo` —
  `PasswordAuth.ValidateSession` only.

These panic if the corresponding middleware has not run; that is a wiring bug,
not a runtime condition to handle.

## Programmatic (non-handler) use

Call `.API()` on any handler type when you need session operations inside
your own handlers or non-HTTP code: `Login`, `Logout`, `StartSession`,
`ValidateSession`, `DestroyAllUserSessions`, `Cookie()`, and (password flow)
credential validation and user management. Example: gRPC interceptors or
custom login endpoints use `StartSession`/`ValidateSession` on a
`context.Context` directly.

## OIDC role management

`NewOIDCAzure` requires a `session.UserRoleManager` (interface in
`session_iface.go`). On every login the callback reconciles the user's roles
to the token's role claims — including *removing* roles not present in the
token — and rejects users with no recognized role. If roles are managed by
the application instead of AD, pass `session.DisableUserRoleManagement()`
(`disable_usermanagement.go`); note the login still requires at least one
role claim in the token. Do not mix IdP-driven and application-driven role
assignment — app-assigned roles are silently reverted at next login.

## Testing

Generated gomock mocks ship with the package: `mock/mock_session` for
`UserRoleManager`, and `sessionstorage/mock/mock_sessionstorage` for the
storage interfaces. Regenerate with `go generate ./mock` (see `mock/mock.go`).
