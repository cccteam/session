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
  - Username/Password
  - Preauth (trust-the-caller stepping-stone sessions)
- `Custom Session Data`: App-defined data attached to each session, resolved atomically at session creation and available to every request. See the "Custom session data" section.
- `Custom User Data`: App-defined durable data attached to the user record — it survives logout, expiry, and regeneration, and dies with the user. See the "Custom user data" section.
- `OIDC User Anchor`: An optional library-managed durable user record for OIDC logins, keyed by the immutable `(tid, oid)` claim pair. See the "OIDC user anchor" section.

All three session types are generic over two data axes: `PasswordAuth[SessionData, UserData]`,
`OIDCAzure[SessionData, UserData]`, and `Preauth[SessionData]` (Preauth has no user record,
so no user-data axis). An application that uses neither instantiates with the
`NoCustomData` sentinel: `session.NewPasswordAuth[session.NoCustomData, session.NoCustomData](storage, cookieKey)`.

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
    userRoleManager, cookieKey, issuerURL, clientID, clientSecret, redirectURL,
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

- **One row per directory identity.** The `OIDCUsers` table (ship the
  `schema/*/oidc/migrations` migration) keys each user by the immutable
  `(tid, oid)` claim pair — the only rename-proof, recycle-proof identity Azure gives
  you — under a surrogate UUID primary key. `Username` (`preferred_username`) is a
  mutable *attribute* on the row, never part of the key.
- **Maintained just-in-time, atomically with login.** Enable it with
  `sessionstorage.WithOIDCUsers()` on the OIDC storage constructor. Inside every
  session-insert transaction the library upserts the row: first login provisions it; a
  login after an IdP rename updates `Username` in place (continuity preserved — no
  orphaned record, no data inherited by a future holder of the old name); every login
  touches `UpdatedAt`. A missing `tid`/`oid` claim aborts the login before any row or
  cookie exists.
- **The durable key flows into your hooks.** `NewSessionRequest.UserID` carries the
  anchor record's ID into the custom session data resolver (copy it into a session
  column to reach the user record from any request without a lookup) and into the
  custom user data hook (below).
- **Read it when you need it.** `oidcSession.API().OIDCUser(ctx, id)` and
  `OIDCUserByKey(ctx, tid, oid)` return the record. Identity comparison in OIDC is
  always `(tid, oid)` — never the username.

```go
storage := sessionstorage.NewSpannerOIDC(client,
    sessionstorage.WithOIDCUsers(),
    /* custom data options */
)
```

The table name defaults to `OIDCUsers` (`session.WithOIDCUserTableName` overrides it).
The anchor is OIDC-only: enabling it on password-auth or preauth storage is a
construction error. It is required for custom user data on OIDC storage.

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
  - **Azure OIDC**: users just *arrive*, known only by their verified claims, so the
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

### Configuration — Azure OIDC with a login hook

The hook is how OIDC user data tracks the directory. It runs inside every OIDC
session-insert transaction — after the `OIDCUsers` anchor upsert, before the session
data resolver — and receives the user's **current row** (`nil` on their first login):

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
    userRoleManager, cookieKey, issuerURL, clientID, clientSecret, redirectURL,
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

##### Created and maintained by the CCC team.
