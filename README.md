# Session

## Overview

The Session repository is designed to handle the management of user sessions, including authorization, storage, and expiration. It provides a framework for managing sessions across different databases and supports multiple login types.

## Features

- `Session Management`: Efficient handling of user session creation, storage, and expiration.
- `Database Support`: Seamless integration with multiple databases.
  - PostgreSQL
  - Google Cloud Spanner
- `Login Types`: Supports multiple authentication methods.
  - Azure OIDC
  - Google Workspace OIDC (restricted to one hosted domain — see the "Google Workspace OIDC" section)
  - Username/Password
  - Preauth (trust-the-caller stepping-stone sessions)
- `Custom Session Data`: App-defined data attached to each session, resolved atomically at session creation and available to every request. See the "Custom session data" section.
- `Custom User Data`: App-defined durable data attached to the user record — it survives logout, expiry, and regeneration, and dies with the user. See the "Custom user data" section.
- `OIDC User Anchor`: An optional library-managed durable user record for OIDC logins, keyed by the provider's immutable identity — the `(tid, oid)` claim pair on Azure, the `sub` claim on Google. See the "OIDC user anchor" section.

All session types are generic over two data axes: `PasswordAuth[SessionData, UserData]`,
`OIDCAzure[SessionData, UserData]`, `OIDCGoogle[SessionData, UserData]`, and
`Preauth[SessionData]` (Preauth has no user record, so no user-data axis). An
application that uses neither instantiates with the `NoCustomData` sentinel:
`session.NewPasswordAuth[session.NoCustomData, session.NoCustomData](storage, cookieKey)`.

## Schema

The DDL for every table the library owns ships as golang-migrate files under
`schema/spanner/` and `schema/postgresql/`: `migrations` (sessions and password-auth
users), `oidc` (Azure OIDC), `oidc-google` (Google Workspace OIDC), and `impersonation`.

**PostgreSQL time columns are `timestamp with time zone`.** The driver writes `time.Time`
values as instants, which `timestamptz` stores faithfully whatever zone the host runs in.
Earlier revisions of the DDL declared `timestamp without time zone`, which keeps the wall
clock and drops the zone: a deployment on that type stays correct as long as every process
writing to it runs in UTC, and such a deployment does not need to migrate. To migrate
anyway, convert the columns and restart the application in the same window — pgx caches
the parameter types of its prepared statements, so a live pool keeps writing wall-clock
values (and fails one cached read per connection) until its connections are recycled:

```sql
-- Repeat for every time column created from the DDL (OIDCUsers/GoogleOIDCUsers
-- CreatedAt and UpdatedAt, the impersonation table's StartedAt/ExpiresAt/EndedAt).
-- 'UTC' names the zone the writing processes ran in.
ALTER TABLE "Sessions"
    ALTER COLUMN "CreatedAt" TYPE timestamptz USING "CreatedAt" AT TIME ZONE 'UTC',
    ALTER COLUMN "UpdatedAt" TYPE timestamptz USING "UpdatedAt" AT TIME ZONE 'UTC';
```

## OIDC role synchronization

Role synchronization reconciles a user's application roles to the identity provider's
authorization signal on every OIDC login: role names sourced from the IdP are assigned
(where a role of that name exists), roles the user holds that are NOT among them are
removed, and the login is rejected unless at least one recognized role results. It is
designed for organizations that manage roles centrally in the directory. The role
names come from the provider's native mechanism — Azure delivers them in the token's
`roles` claim (App Role ↔ group assignments); Google has no such claim, so the Google
flow derives them from Google Groups membership at login (see the "Google Workspace
OIDC" section). See the `OIDCAzure` and `OIDCGoogle` godoc for the full semantics and
their multi-tenancy limitations.

The `NewOIDCAzure` constructor takes a required role-sync slot that
configures the feature as one unit — the role store together with the domain sweep
list:

```go
// Enabled: reconcile against the global domain plus the app's tenant domains.
// The domains provider is called at every login, so tenants created between
// logins are included. Global-only apps pass a nil provider.
oidcSession, err := session.NewOIDCAzure[session.NoCustomData, session.NoCustomData](
    storage,
    session.RoleSync(userRoleManager, func(ctx context.Context) ([]accesstypes.Domain, error) {
        return app.TenantDomains(ctx) // the app owns the tenant table
    }),
    cookieKey, issuerURL, clientID, clientSecret, redirectURL,
)

// Disabled (application-managed roles, or no roles at all): no roles are read,
// written, or removed at login, and the at-least-one-role gate does not apply.
oidcSession, err := session.NewOIDCAzure[session.NoCustomData, session.NoCustomData](
    storage, session.DisableRoleSync(),
    cookieKey, issuerURL, clientID, clientSecret, redirectURL,
)
```

The sweep list is deliberately a required, explicit input rather than an option with a
default: there is no safe universal default for a multi-tenant application — a
global-only default would compile and log users in while silently never assigning (or
sweeping) their tenant-domain roles. `accesstypes.GlobalDomain` is always included
implicitly; the provider returns tenant domains only.

Migrating from the previous two-parameter shape (`NewOIDCAzure(storage,
userRoleManager, ...)`): wrap the manager in `session.RoleSync(manager, domainsFn)` —
the manager no longer supplies the domain list (`Domains` left the `UserRoleManager`
interface, and `RoleExists` now returns `(bool, error)`; its errors abort the sync
rather than being flattened to "role missing", which would delete valid memberships on
a transient store error). Replace `session.DisableUserRoleManagement()` with
`session.DisableRoleSync()` — note that unlike the old disabled manager, it also
disables the at-least-one-role login gate.

## Google Workspace OIDC

`OIDCGoogle` is the Google Workspace counterpart of `OIDCAzure`: the same session
machinery, custom data axes, and role-reconciliation semantics, built on Google's
identity model instead of Entra's. The mental-model difference that drives every API
difference: **an Entra app registration is an authorization surface** (App Roles are
declared on the app, assigned to groups, and delivered in the token's `roles` claim),
while **a Google OAuth client is authentication only** — the ID token says who the user
is (`email`, `sub`) and which Workspace org they belong to (`hd`), and nothing about
what they may do. Authorization signals therefore come from the directory itself
(Google Groups), fetched at login.

### Restricting login to your organization

Two layers, one enforced by Google and one by this library:

1. **Internal OAuth consent screen** (Google-side): create the OAuth client in a Google
   Cloud project that belongs to your Workspace org and set the consent screen's user
   type to *Internal*. Google then refuses accounts outside the org (`org_internal`
   error) before they ever reach your callback.
2. **`hostedDomain`** (library-side, required): sent as the `hd` hint on the
   authorization request (pre-selects org accounts in the account chooser — UX only),
   and enforced against the verified ID token's `hd` claim. A consumer account carries
   no `hd` claim at all, so the check fails closed. This is the trusted backstop even
   with an Internal consent screen in place.

### Constructing

```go
// Directory-driven roles: Google Groups membership is fetched at login through a
// GroupsProvider and mapped to role names by a group naming convention.
groups, err := googlegroups.NewDirectory(ctx, credentialsJSON, "groups-reader@example.com")
if err != nil { ... }

oidcSession, err := session.NewOIDCGoogle[session.NoCustomData, session.NoCustomData](
    storage, // sessionstorage.NewSpannerGoogleOIDC / NewPostgresGoogleOIDC
    session.GoogleRoleSync(userRoleManager, domainsFn, "app-myapp-", groups),
    cookieKey, clientID, clientSecret, redirectURL,
    "example.com", // hostedDomain — required
)

// Application-managed roles (or no roles): same slot as Azure.
oidcSession, err := session.NewOIDCGoogle[session.NoCustomData, session.NoCustomData](
    storage, session.DisableRoleSync(),
    cookieKey, clientID, clientSecret, redirectURL, "example.com",
)
```

There is no `issuerURL` parameter — Google operates a single issuer
(`https://accounts.google.com`) for all orgs; tenancy is the `hd` claim, not the
issuer. The storage must be Google OIDC storage (`NewSpannerGoogleOIDC` /
`NewPostgresGoogleOIDC`, migrations in `schema/*/oidc-google/migrations`); the Azure
role-sync slot and Azure OIDC storage do not compile into `NewOIDCGoogle`.

### The group naming convention

`GoogleRoleSync` derives candidate role names from group emails: a group whose local
part is the configured prefix followed by a role name maps to that role, everything
else is ignored. With prefix `app-myapp-`:

| Group email                       | Candidate role |
| --------------------------------- | -------------- |
| `app-myapp-admin@example.com`     | `admin`        |
| `app-myapp-viewer@example.com`    | `viewer`       |
| `team-eng@example.com`            | — (no prefix)  |
| `app-otherapp-admin@example.com`  | — (other app)  |

The candidates then flow through the same reconcile logic as Azure's token roles: names
for which a role exists are assigned, held roles not among them are removed, and the
login is rejected unless at least one recognized role results. Group emails are
lowercase by nature, so define application roles intended for Google sync with
lowercase names. Membership is resolved through the `GroupsProvider` seam:

- `googlegroups.NewDirectory` (provided): Admin SDK Directory API, available on every
  Workspace edition, **direct memberships only** (role groups should hold people, not
  other groups — matching Entra's direct-only App Role resolution). It authenticates as
  a service account with domain-wide delegation on the
  `admin.directory.group.readonly` scope, impersonating an account whose only admin
  privilege is *Groups → Read* (a custom admin role; no Super Admin).
- A `CloudIdentity` adapter (transitive expansion via `searchTransitiveGroups`) is
  deliberately reserved for the future: that API requires Workspace Enterprise /
  Cloud Identity Premium, enforced per queried member.

A groups-lookup failure fails the login — the same posture as a role-store error.

### Identity and the other differences from Azure

| Concern                | Azure (`OIDCAzure`)                  | Google (`OIDCGoogle`)                          |
| ---------------------- | ------------------------------------ | ---------------------------------------------- |
| Username               | `preferred_username` claim           | `email` claim (`email_verified` enforced)      |
| Durable identity key   | `(tid, oid)` — oid is tenant-scoped  | `sub` alone — globally unique, never reused    |
| User anchor table      | `OIDCUsers`                          | `GoogleOIDCUsers` (`Hd`/`Username` mutable attributes) |
| Roles source           | Token `roles` claim                  | Google Groups lookup + naming convention       |
| Org restriction        | Single-tenant registration / `tid`   | Internal consent screen + `hostedDomain` (`hd`) |
| IdP-initiated logout   | `FrontChannelLogout` (`sid` claim)   | None — Google has no `end_session_endpoint` or `sid`; `Logout` destroys the local session only |

## Custom session data

Custom session data attaches app-specific values to a session — a selected tenant, a role
snapshot, an impersonation context. The values live in a table you own (one row per
session), are written when the session is created, and are available to every request for
the life of the session.

How it works:

- **One struct declares your data.** Each tagged field of your struct `T` maps to a
  column in your table (`spanner:"TenantId"` / `db:"TenantId"`). The library reflects
  over `T` once at startup to derive the columns — there is no hand-written decoder
  and no column list to maintain.

- **A resolver writes it — once, at creation.** Your resolver runs **inside the same
  transaction that inserts the session row** (login, external auth, session
  regeneration) and returns the `*T` to store, committed atomically with the session.
  If it returns an error, the login fails: no session, no cookies.

- **Every request reads it — automatically.** Session validation fetches the custom
  row together with the session (a single `LEFT JOIN` query) and your handlers get a
  typed `T` back with `auth.API().CustomData(ctx)`. No second round-trip, no manual
  decoding.

- **Mid-session changes are deliberate.** `UpdateCustomSessionData` is a transactional
  read-modify-write: a typed callback mutates the current row and the full row is
  written back. It exists for *changing* state mid-flight (a tenant switcher) — never
  for initial population.

- **Everything is checked at startup.** The session type is generic over the same
  struct (`PasswordAuth[MyData, ...]`), and construction verifies the storage's custom
  data config was built for it. Misconfiguration is a boot failure, not a request-time
  surprise.

- **Cleanup is the database's job.** Sessions are marked expired in place; your
  `ON DELETE CASCADE` foreign key removes the custom row whenever a session row is
  deleted. Regeneration (e.g. a password change) re-resolves fresh — updates don't
  carry over.

That is the whole model: **declare with tags, resolve once, read typed, update
deliberately.** Everything below is reference detail.

One boundary before the details: this is **session data** — born with the session, reset
when the session is regenerated, gone when the session dies. Durable facts about the
*person* (profile fields, provisioning state) belong with the user record — see the
"Custom user data" section below and
[docs/data-storage-guidance.md](docs/data-storage-guidance.md).

### Schema requirements

You create the table. The contract:

- A primary-key column named `SessionId` that is a **foreign key to the session table's
  primary key with `ON DELETE CASCADE`**.
- Never tag a field `SessionId` — it is implied and reserved.
- The resolver (or per-call data) writes the **full row** from `T`, so every tagged field
  is always written — plan `NOT NULL` constraints accordingly.
- **Columns that can hold `NULL` must map to nullable Go types** (Spanner:
  `spanner.NullString` and friends, or pointers; Postgres: pointer fields). Scanning a
  `NULL` into a non-nullable field is a request-failing error.

```sql
-- Spanner
CREATE TABLE SessionCustomData (
    SessionId STRING(36) NOT NULL,
    TenantId  STRING(36),
    RoleId    STRING(MAX),
    CONSTRAINT FK_SessionCustomData_Sessions FOREIGN KEY (SessionId)
        REFERENCES Sessions(Id) ON DELETE CASCADE,
) PRIMARY KEY (SessionId);
```

### The struct-tag contract

The library never introspects your schema. The same identifiers must agree in two places:

1. **Your DDL** — the physical columns.
2. **`T`'s struct tags** — the `spanner:"..."` (Spanner) or `db:"..."` (Postgres) tag on
   each exported field names its column. An untagged exported field uses the field name;
   a `-` tag skips the field; embedded structs contribute their promoted fields.

The derived columns drive the `SELECT c.<name>` list on every read *and* the INSERT
columns at creation. Names are validated for shape at construction (letter/underscore
start, ≤128 chars), but whether they exist in your table is discovered by the database —
a mismatch surfaces as a query error.

### Configuration — username/password with a resolver

The struct and resolver are declared together with the table name in one validated
config unit, attached to the storage via a typed option, and the session type is built
for the same `T`:

```go
type MyData struct {
    TenantID string `spanner:"TenantId"`
    RoleID   string `spanner:"RoleId"`
}

customCfg, err := sessionstorage.NewSpannerCustomSessionData(
    "SessionCustomData",
    func(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*MyData, error) {
        // resolver: runs ONCE per session creation, inside the insert transaction.
        // req carries Reason (Login | ExternalAuth | Regeneration | Preauth),
        // Username, UserID, and Claims (OIDC).
        user, err := loadUser(ctx, txn, req.UserID)     // reads are txn-consistent
        if err != nil {
            return nil, err                             // aborts the login
        }
        return &MyData{TenantID: user.TenantID, RoleID: user.RoleID}, nil
    },
)
if err != nil { /* non-struct T, no persistable fields, invalid identifier, reserved SessionId, ... */ }

auth, err := session.NewPasswordAuth[MyData, session.NoCustomData](
    sessionstorage.NewSpannerPasswordAuth(client,
        sessionstorage.WithSpannerCustomSessionData(customCfg)),
    cookieKey,
    /* other options */
)
```

`T` is inferred from the resolver's return type; with a `nil` resolver, name it
explicitly: `NewSpannerCustomSessionData[MyData]("SessionCustomData", nil)`. A `nil`
resolver means session creation performs a plain insert, and custom data comes only from
per-call values (below) or `UpdateCustomSessionData`. The Postgres mirror
(`NewPostgresCustomSessionData`, resolver over `pgx.Tx`, `db:"..."` tags,
`WithPostgresCustomSessionData`) is identical in shape; configs are backend-typed, so
attaching a Spanner config to a Postgres storage does not compile.

The second type parameter is the custom **user** data struct (see "Custom user data");
apps that use neither axis instantiate both with `session.NoCustomData`.

### Configuration — Azure OIDC from verified claims

For OIDC logins the resolver receives the **complete raw verified ID-token claims** as
`req.Claims json.RawMessage` — the library does not curate a claims struct; unmarshal the
fields you need. A resolver error aborts the login before any cookie is written and the
user is redirected to the login page with the error's client message.

```go
type SessionClaims struct {
    Oid   string `json:"oid"   spanner:"Oid"`
    Name  string `json:"name"  spanner:"Name"`
    Email string `json:"email" spanner:"Email"`
}

customCfg, err := sessionstorage.NewSpannerCustomSessionData(
    "SessionClaimsData",
    func(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*SessionClaims, error) {
        c := &SessionClaims{}
        if err := json.Unmarshal(req.Claims, c); err != nil {
            return nil, err
        }
        // With the OIDC user anchor enabled, req.UserID already holds the durable
        // OIDCUsers record's ID — copy it into a column here to reach the user
        // record from any request without a lookup (see "OIDC user anchor").
        return c, nil
    },
)

oidcSession, err := session.NewOIDCAzure[SessionClaims, session.NoCustomData](
    sessionstorage.NewSpannerOIDC(client, sessionstorage.WithSpannerCustomSessionData(customCfg)),
    session.RoleSync(userRoleManager, tenantDomains), // see "OIDC role synchronization"
    cookieKey, issuerURL, clientID, clientSecret, redirectURL,
)
```

Note: role synchronization runs before session creation, so a login rejected for having
no recognized role never creates a session or writes cookies; the resolver runs after
role sync, inside the session-insert transaction. Token roles are also available
directly in the raw claims.

### Reading the data in handlers

```go
data, err := auth.API().CustomData(ctx)                    // returns MyData
// or, without the session type in scope:
data, err := sessioninfo.CustomDataFromCtx[*MyData](ctx)   // note: pointer type
```

The context stores a `*T` (pointer to the config's struct type), so `CustomDataFromCtx`
must be instantiated with the pointer type; `API().CustomData` hides this and returns the
value. Because the read is a `LEFT JOIN`, a session with **no** custom row still loads —
it yields a **zero-value `T`**, not an error.

### Per-call custom data

When the values come from the request rather than from config-time logic, pass the row
directly at session creation — written atomically with the insert, and **the configured
resolver is skipped for that creation (per-call data wins)**:

```go
// Password auth, externally-authenticated users (e.g. admin impersonation):
sessionID, err := auth.API().StartAuthenticatedSession(ctx, w, username,
    &MyData{TenantID: tenantID, RoleID: roleID},
)

// Preauth (trust-the-caller):
sessionID, err := preauth.API().Login(ctx, w, username,
    &MyData{TenantID: tenantID},
)
```

At most one value may be passed — it is the complete custom data row. Per-call data
requires a custom session data configuration on the storage (the config may have a nil
resolver). Passing data with no configuration attached is an error before anything is
inserted.

### Mid-session updates

Some session state legitimately changes while the session is alive — the canonical case
is a **tenant switcher**: the resolver records the user's default tenant at login, and the
user later selects a different one. That is what `UpdateCustomSessionData` is for:

```go
err := auth.API().UpdateCustomSessionData(ctx, sessionID, func(data *MyData) error {
    data.TenantID = newTenantID

    return nil
})
```

It is available on all three session types: `PasswordAuthAPI`, `OIDCAzureAPI`,
and `PreauthAPI`.

Semantics to know:

- **It is a transactional read-modify-write.** The current row is read (zero-value `T`
  when the session has no row yet), your callback mutates it, and the **full row** is
  written back — fields you don't touch are preserved, because they ride along in `data`.
  A callback error aborts the transaction with nothing written. Concurrent updates are
  serialized by the transaction; last committed callback wins.
- **It takes effect on the next request** — the per-request read picks up the new
  values; requests already in flight see the old ones.
- **The library does not authorize the change.** The resolver established what the user
  was granted at login; before writing a switch, your handler must verify the user is
  allowed the new value (e.g. is a member of the target tenant).
- **Updates do not survive regeneration.** A password change re-resolves fresh and the
  selected value reverts to the resolver's answer (see Session regeneration).
- Expired sessions are rejected; a custom data configuration must be attached.

The rule of thumb for choosing the verb: **resolve** for identity-derived state
(what the user *is* at login), **update** for user-chosen context within
already-granted options (which tenant they're *looking at*), and **regenerate/destroy**
for privilege changes — if a user's rights change, kill their sessions rather than
patching them (`DestroyAllUserSessions`); the next login re-resolves.

Never use `UpdateCustomSessionData` for initial population — that belongs in the creation
transaction (resolver or per-call data), which is atomic with the session insert.

### Session regeneration

A password change destroys all of the user's sessions and starts a fresh one for the
caller (session-fixation protection). Custom session data is **resolved fresh** for the
new session — the resolver runs again with `Reason: ReasonRegeneration` — and values
previously written via `UpdateCustomSessionData` do **not** carry over. If losing a value
on regeneration feels like data loss, it was user data, not session data — see
[docs/data-storage-guidance.md](docs/data-storage-guidance.md).

### Where failures surface

| Misconfiguration / failure | Surfaces as |
|---|---|
| Non-struct `T`, no persistable fields, invalid tag identifier, reserved `SessionId`, duplicate columns | Error from the config constructor, at startup |
| Session type's `T` doesn't match the storage config's `T` (or no config attached) | Error from the session-type constructor, at startup |
| Wrong-backend config on a storage constructor | Compile error |
| Resolver returns an error | Session creation aborts atomically: no session row, no custom row, no cookies; login fails (OIDC: redirect to login with the error's client message) |
| Per-call data with no config attached, or more than one per-call value | Error before any insert |
| Column name not in your DDL | Database error from the creation transaction (aborts atomically) or from the per-request query |
| `NULL` column scanned into a non-nullable field | The request fails (401) — map nullable columns to nullable Go types |
| `UpdateCustomSessionData` callback returns an error | Transaction aborts; nothing written |
| `UpdateCustomSessionData` on an expired session | Rejected (bad request); the row is not written |
| Session has no custom row | Not a failure: reads yield a zero-value `T` (LEFT JOIN) |

## OIDC user anchor

The OIDC user anchor is an optional, library-managed **durable user record for OIDC
logins** — the OIDC counterpart of password auth's `SessionUsers` table. Password auth
always has a stable, rename-safe user key (`SessionUsers.Id`); OIDC historically had
none, which pushed apps toward keying durable data on the username — a mutable,
recyclable identifier (see AP-1 in
[docs/data-storage-guidance.md](docs/data-storage-guidance.md)). The anchor closes that
gap.

How it works:

- **One row per directory identity, keyed by the provider's immutable identity.** On
  Azure, the `OIDCUsers` table (ship the `schema/*/oidc/migrations` migration) keys
  each user by the immutable `(tid, oid)` claim pair — the only rename-proof,
  recycle-proof identity Azure gives you (`oid` is only unique within a tenant) —
  under a surrogate UUID primary key. On Google, the `GoogleOIDCUsers` table (ship the
  `schema/*/oidc-google/migrations` migration) keys each user by the `sub` claim
  alone — globally unique among all Google accounts and never reused — with `Hd` as a
  mutable attribute alongside `Username`. In both cases `Username`
  (`preferred_username` on Azure, `email` on Google) is a mutable *attribute* on the
  row, never part of the key.
- **Maintained just-in-time, atomically with login.** Enable it with
  `sessionstorage.WithOIDCUsers()` on the OIDC storage constructor. Inside every
  session-insert transaction the library upserts the row: first login provisions it; a
  login after an IdP rename updates `Username` in place (continuity preserved — no
  orphaned record, no data inherited by a future holder of the old name); every login
  touches `UpdatedAt`. A missing key claim (`tid`/`oid` on Azure, `sub`/`hd` on Google)
  aborts the login before any row or cookie exists.
- **The durable key flows into your hooks.** `NewSessionRequest.UserID` carries the
  anchor record's ID into the custom session data resolver (copy it into a session
  column to reach the user record from any request without a lookup) and into the
  custom user data hook (below).
- **Read it when you need it.** On Azure, `oidcSession.API().OIDCUser(ctx, id)` and
  `OIDCUserByKey(ctx, tid, oid)` return the record; on Google, `GoogleOIDCUser(ctx,
  id)` and `GoogleOIDCUserBySub(ctx, sub)`. Identity comparison in OIDC is always the
  provider's immutable key — never the username.

```go
storage := sessionstorage.NewSpannerOIDC(client, // or NewSpannerGoogleOIDC
    sessionstorage.WithOIDCUsers(),
    /* custom data options */
)
```

`WithOIDCUsers()` is provider-neutral — it enables *the anchor*, and the storage it is
applied to defines the anchor's shape. The table name defaults to `OIDCUsers` on Azure
storage and `GoogleOIDCUsers` on Google storage (`session.WithOIDCUserTableName`
overrides either). The anchor is OIDC-only: enabling it on password-auth or preauth
storage is a construction error. It is required for custom user data on OIDC storage.

## Custom user data

Custom user data is the durable counterpart of custom session data: app-defined values
attached to the **user record** — a locale, provisioning state, profile fields synced
from the IdP. Where session data is born and dies with one login, user data **survives
logout, session expiry, and regeneration, and dies with the user** (your
`ON DELETE CASCADE` FK removes it when the user row is deleted).

The mechanism mirrors custom session data deliberately — declare with tags, one
validated config unit per backend, typed reads, transactional RMW updates — with two
differences that follow from durability:

- **Reads are on demand, never per-request.** User data is *not* joined into the
  session read and never appears in the request context; fetch it when you need it with
  `API().CustomUserData(ctx, userID)`. A user with no row yields a zero-value `U`.
- **The write path depends on the auth mode**, because the two modes learn about users
  differently:
  - **Password auth**: users are created explicitly, so initial data is **per-call on
    `CreateSessionUser`**, written atomically with the user insert. There is no
    login-time hook — password logins carry no claims.
  - **OIDC (Azure and Google)**: users just *arrive*, known only by their verified claims, so the
    config carries a **login hook** that runs inside every OIDC session-insert
    transaction, after the anchor upsert (requires the OIDC user anchor).
  - **Preauth**: unsupported — there is no user record to anchor durable data to
    (construction error if configured).

### Schema requirements

Identical to the session-data contract with one substitution: the primary-key column is
named `UserId` and is a **foreign key with `ON DELETE CASCADE`** to `SessionUsers(Id)`
(password auth) or `OIDCUsers(Id)` (OIDC). Never tag a field `UserId` — it is implied
and reserved. Nullable columns must map to nullable Go types.

```sql
-- Spanner, password auth
CREATE TABLE UserCustomData (
    UserId  STRING(36) NOT NULL,
    Locale  STRING(MAX),
    Theme   STRING(MAX),
    CONSTRAINT FK_UserCustomData_SessionUsers FOREIGN KEY (UserId)
        REFERENCES SessionUsers(Id) ON DELETE CASCADE,
) PRIMARY KEY (UserId);
```

### Configuration — password auth

```go
type UserData struct {
    Locale string `spanner:"Locale"`
    Theme  string `spanner:"Theme"`
}

userCfg, err := sessionstorage.NewSpannerCustomUserData[UserData]("UserCustomData", nil)

auth, err := session.NewPasswordAuth[MyData, UserData](
    sessionstorage.NewSpannerPasswordAuth(client,
        sessionstorage.WithSpannerCustomSessionData(sessCfg),
        sessionstorage.WithSpannerCustomUserData(userCfg)),
    cookieKey,
)

// Create: initial data lands atomically with the user insert (at most one value —
// it is the complete row). Omit it for a plain insert (reads yield zero-value U).
id, err := auth.API().CreateSessionUser(ctx, req, &UserData{Locale: "en-AU"})

// Read: on demand, by user ID — never from the session context.
u, err := auth.API().CustomUserData(ctx, userID)

// Update: transactional read-modify-write, same contract as session data —
// mutate the current row (zero-value U when none) and the full row is written back.
err = auth.API().UpdateCustomUserData(ctx, userID, func(d *UserData) error {
    d.Theme = "dark"

    return nil
})
```

### Configuration — OIDC with a login hook

The hook is how OIDC user data tracks the directory, and it works identically for
Azure and Google (the anchor upsert it follows is `OIDCUsers` or `GoogleOIDCUsers`
respectively). It runs inside every OIDC session-insert transaction — after the anchor
upsert, before the session data resolver — and receives the user's **current row**
(`nil` on their first login):

```go
type UserProfile struct {
    // IdP-owned: sourced from claims, refreshed by the hook
    Email       spanner.NullString `spanner:"Email"`
    DisplayName spanner.NullString `spanner:"DisplayName"`
    // App-owned: written via UpdateCustomUserData, untouched by the hook
    Theme       spanner.NullString `spanner:"Theme"`
}

userCfg, err := sessionstorage.NewSpannerCustomUserData("OIDCUserData",
    func(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest, current *UserProfile) (*UserProfile, error) {
        var c struct {
            Email string `json:"email"`
            Name  string `json:"name"`
        }
        if err := json.Unmarshal(req.Claims, &c); err != nil {
            return nil, err // aborts the login: no anchor change, no row, no session
        }
        if current == nil { // first login: provision row one
            return &UserProfile{Email: ns(c.Email), DisplayName: ns(c.Name)}, nil
        }
        if current.Email.StringVal == c.Email && current.DisplayName.StringVal == c.Name {
            return nil, nil // directory unchanged: zero writes this login
        }
        // Refresh ONLY the IdP-owned fields. Theme survives because we start
        // from current — returning a fresh &UserProfile{} would zero it.
        current.Email, current.DisplayName = ns(c.Email), ns(c.Name)

        return current, nil // full-row upsert, atomic with the login
    })

oidcSession, err := session.NewOIDCAzure[SessionClaims, UserProfile](
    sessionstorage.NewSpannerOIDC(client,
        sessionstorage.WithOIDCUsers(), // the anchor is required for OIDC user data
        sessionstorage.WithSpannerCustomSessionData(sessCfg),
        sessionstorage.WithSpannerCustomUserData(userCfg)),
    session.RoleSync(userRoleManager, tenantDomains),
    cookieKey, issuerURL, clientID, clientSecret, redirectURL,
)
```

Hook contract, precisely: `current` is the existing row read in the same transaction
(`nil` when none); returning `nil, nil` leaves the row untouched; returning a `*U`
upserts it as the **full row** — start from `current` when refreshing individual
fields, or app-written fields are zeroed (the same footgun contract as the RMW update);
returning an error aborts the whole login atomically. The hook never runs outside OIDC
session creation, and a `nil` hook is valid (write-API-only user data).

### Where failures surface

| Misconfiguration / failure | Surfaces as |
|---|---|
| Non-struct `U`, invalid tag identifier, reserved `UserId`, duplicate columns | Error from the config constructor, at startup |
| Session type's `U` doesn't match the storage config's `U` (or no config attached) | Error from the session-type constructor, at startup |
| Custom user data on OIDC storage without `WithOIDCUsers()` | Error from `NewOIDCAzure`, at startup |
| Login hook on password-auth storage, or any user data config on preauth storage | Error from the session-type constructor, at startup |
| `WithOIDCUsers()` on password-auth or preauth storage | Error from the session-type constructor, at startup |
| Missing `tid`/`oid` claim with the anchor enabled | Login aborts: no anchor row, no user data, no session, no cookies |
| Login hook returns an error | Login aborts atomically (anchor upsert included) |
| Per-call data on `CreateSessionUser` with no config attached, or more than one value | Error before any insert |
| `UpdateCustomUserData` for a user ID that doesn't exist | Not-found error; nothing written |
| User has no custom row | Not a failure: reads and RMW yield a zero-value `U` |

## Impersonated sessions

An impersonated session operates as a principal other than the person who
authenticated: as another **user** (support staff seeing the application exactly as
that user does, usually read-only) or as a **role** (an administrator working under a
role chosen for the session). Every session type supports both — password auth,
Preauth, OIDC Azure and OIDC Google — through the same `ImpersonationRequest` on each
`API()`.

The model rests on two identities that are never conflated:

- **Actor** — who authenticated. Constant for the session's life; the identity audit
  and attribution always name.
- **Principal** — what permission checks evaluate against
  (`accesstypes.UserPrincipal` or `accesstypes.RolePrincipal`).

**A session is a session.** Once established, an impersonated session flows through
`ValidateSession`, `sessioninfo`, custom session data and every handler exactly as an
ordinary session does. The session's `Username` is its *effective identity*: the
impersonated user for a user principal (so every consumer sees precisely what that user
would see), or the actor for a role principal (nobody's identity is borrowed). The
**impersonation record** — not the username — is what marks the session as
impersonated, and only the way the session is *established* is new.

### Enabling

Create the record table from the shipped DDL
(`schema/{spanner,postgresql}/impersonation/migrations`) and attach it to the storage.
The table deliberately has **no foreign key to the session table**: the record is
evidence and outlives the session; retention is the application's policy.

```go
imp, err := sessionstorage.NewImpersonationTable("SessionImpersonations")

auth, err := session.NewPasswordAuth[MyData, session.NoCustomData](
    sessionstorage.NewSpannerPasswordAuth(client,
        sessionstorage.WithSpannerCustomSessionData(sessCfg),
        sessionstorage.WithImpersonation(imp)),
    cookieKey,
    session.WithImpersonationTimeout(time.Hour),        // hard cap; default one hour
    session.WithImpersonationAudit(func(ctx context.Context, e sessioninfo.ImpersonationEvent) error {
        return auditTrail.Record(ctx, e)                 // Started, Ended, IdentityOperationBlocked
    }),
)
```

The same `WithImpersonation` option and `WithImpersonationTimeout` /
`WithImpersonationAudit` session options apply to `NewPreauth`, `NewOIDCAzure` and
`NewOIDCGoogle`. Without `WithImpersonation` nothing changes: no session is ever
impersonated and the impersonation APIs return a configuration error.

### Establishing a session

The establishing call runs in the *target* application's session API, typically from a
server-to-server handoff (an admin application minting a session in a partner portal):

```go
// Support views bob's portal, read-only, for an hour at most.
id, err := auth.API().StartImpersonatedSession(ctx, w, &session.ImpersonationRequest{
    Actor:      "alice@example.com",
    ActorRealm: "admin-portal",
    Principal:  accesstypes.UserPrincipal("bob@partner.org"),
    Mask:       accesstypes.MaskPermissions(accesstypes.List, accesstypes.Read),
    Reason:     "ticket JRN-123",
})

// An administrator works the partner portal under a role.
id, err := auth.API().StartImpersonatedSession(ctx, w, &session.ImpersonationRequest{
    Actor:     "alice@example.com",
    Principal: accesstypes.RolePrincipal("PartnerViewer"),
}, &MyData{PartnerID: partnerID}) // custom session data rides along as usual
```

The session row and the record are written in one transaction; the cookie is set only
after the `Started` event has been delivered (a failing audit hook destroys the session
and fails the call). Refused everywhere: a missing actor or principal, and a caller that
is itself an impersonated session (no chaining). *Who may impersonate whom* is the
application's guard — the library records what happened.

#### Identity by session type

A role principal's session is always the actor's: nobody's identity is borrowed. What a
**user** principal resolves to depends on what the session type knows about users:

| Session type | User principal becomes | User ID | Refused |
| --- | --- | --- | --- |
| Password auth | The `SessionUsers` record's username | The record's ID | A missing or disabled user |
| Preauth | The name as given | Zero | — (trust-the-caller, as `Login` is) |
| OIDC Azure / Google | The name as given (what a login would take from the token) | Zero | — |

An impersonated OIDC session authenticates no ID token: no OIDC user anchor is upserted,
no roles are synchronized, and the configured custom session data resolver receives
`ReasonImpersonation` with no claims. The row carries no identity provider session ID,
so `FrontChannelLogout` never ends it — it ends by its hard cap, idle expiry, `Logout`,
or `DestroyImpersonatedSessions`. Minting an impersonated session in the same
application the actor is logged into replaces the browser's session cookie; pass the
actor's session as `SourceSessionID` to keep the link.

### What the session carries

Every validated request exposes the record without branching on whether the session is
impersonated:

```go
principal := sessioninfo.PrincipalFromCtx(ctx) // UserPrincipal(username) for an ordinary session
actor     := sessioninfo.ActorFromCtx(ctx)     // == Username unless impersonated
mask      := sessioninfo.MaskFromCtx(ctx)      // unrestricted unless impersonated
imp, ok   := sessioninfo.ImpersonationFromCtx(ctx)
```

A permission check honors the mask by asking it before asking policy —
`sessioninfo.MaskFromCtx(ctx).Allows(perm)` — and picks the check by the principal's
kind (`Role()` → `CheckRoleResources`, otherwise `CheckUserResources`). Forgetting the
mask fails *open*, so prefer a shared implementation over hand-rolling it per
application.

### Choosing the principal

By default a session's principal is its user, or the impersonation record's principal.
Some applications want a session to act as something else without impersonating anyone
— a partner portal whose every session acts as the role it was minted with, carried in
custom session data. `WithPrincipalResolver` is that seam: the resolver runs inside
session validation, with the session, its custom data and its impersonation record in
the context, and returns the principal `PrincipalFromCtx` reports for the request.

```go
auth, err := session.NewPreauth[PortalData](storage, cookieKey,
    session.WithPrincipalResolver(func(ctx context.Context) (accesstypes.Principal, error) {
        data, err := sessioninfo.CustomDataFromCtx[*PortalData](ctx)
        if err != nil {
            return accesstypes.Principal{}, err
        }

        return accesstypes.RolePrincipal(accesstypes.Role(data.RoleID)), nil
    }),
)
```

- The choice is made per request at validation and never stored; nothing changes in the
  schema and no impersonation record is written.
- The resolver runs for ordinary sessions and for user-principal impersonations — an
  impersonated user's session acts as that user's session would. A role-principal
  impersonation already names its subject and skips the resolver.
- Returning the zero `Principal` keeps the default. An error fails the request as a
  server error, not an unauthorized one: the session is valid; the application could not
  decide what it acts as.
- When the resolver changes the principal, the request's log entry carries
  `principal.kind` and `principal` (`sessioninfo.AttrPrincipalKind`,
  `sessioninfo.AttrPrincipal`); unchanged requests carry nothing extra.

### Evidence

Everything an impersonated session touches names the actor and the principal:

| Evidence | Where |
| --- | --- |
| The record (actor, realm, source session, principal, mask, reason, started/expires/ended, end reason) | The impersonation table, durable |
| `impersonation.actor`, `.actor_realm`, `.principal_kind`, `.principal`, `.mask`, `.session_id`, `.source_session_id` | The request-level log entry and every line logged within the request (constants in `sessioninfo`) |
| `principal.kind`, `principal` — when a `WithPrincipalResolver` changed the request's subject | The request-level log entry and every line logged within the request |
| `Started` / `Ended` / `IdentityOperationBlocked` / `WriteBlocked` events | Structured log lines, plus the `WithImpersonationAudit` hook |
| The establishing call's own log entry | The source application's request log |
| `impersonation` object in the `Authenticated()` response | For the frontend to banner the session and render read-only affordances |

### Lifecycle and guards

- **Hard cap.** `ExpiresAt` is fixed at establishment (`WithImpersonationTimeout`,
  default one hour, shortened per call by `MaxDuration`); idle renewal never extends past
  it. The idle session timeout applies independently.
- **Ending.** Logout, the hard cap, idle expiry, and `DestroyAllUserSessions` all end
  the record with a reason (`Logout`, `Expired`, `Revoked`). `API().DestroyImpersonatedSessions(ctx, actor)`,
  on every session type, is the offboarding and incident tool: it expires every live
  impersonated session an actor established.
- **Validation (password auth).** A user principal's record is looked up like any
  session's — a disabled impersonated user ends the session. A role principal has no
  local user: no record is looked up and `UserFromCtx` carries the actor's username with
  the zero ID, so self-referential checks (cannot delete yourself) go inert, correctly.
  Preauth and OIDC validate an impersonated session exactly as any other.
- **Identity operations.** The library's own handlers refuse under impersonation:
  `ChangeUsername` and `ChangeUserPassword` always (they would alter the impersonated
  user's credentials); `CreateUser`, `DeactivateUser`, `DeleteUser` and `ActivateUser`
  when the session is masked. Each refusal is an `IdentityOperationBlocked` event.
- **Listing.** `API().ActiveImpersonations(ctx, q)`, on every session type, lists the
  impersonated sessions that are live right now, newest first — the admin surface's view
  of who is acting as whom. *Active* means: the record has not ended, the hard cap has
  not passed, the session row is not expired, and the session has seen activity within
  the idle session timeout. `q` (`*session.ImpersonationQuery`) narrows by `Actor`
  and/or `Principal`; `nil` lists everything.

  ```go
  imps, err := auth.API().ActiveImpersonations(ctx, &session.ImpersonationQuery{Actor: "alice@example.com"})
  ```
- **Read-only middleware.** `EnforceReadOnlyMask` (on every session type, after
  `ValidateSession`) refuses non-safe requests — anything but GET, HEAD, OPTIONS and
  TRACE — from a session whose mask is *read-only*: restricted, and allowing nothing
  beyond `List` and `Read`. The refusal is 403 with a `WriteBlocked` event naming the
  method and path. It is an opt-in backstop that keeps a read-only session away from
  every mutating handler whether or not that handler consults the mask; it does not
  replace honoring the mask in permission checks (`Execute` reaches handlers by POST, and
  a mask including `Execute` is not read-only).

  ```go
  r.Group(func(r chi.Router) {
      r.Use(auth.ValidateSession, auth.ValidateXSRFToken, auth.EnforceReadOnlyMask)
      // ...
  })
  ```

##### Created and maintained by the CCC team.
