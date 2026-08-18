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
- `Custom Session Data`: App-defined data attached to each session, resolved atomically at session creation and available to every request. See the next section.

## Custom session data

Custom session data attaches app-specific values to a session — a selected tenant, a role
snapshot, an impersonation context. The values live in a table you own (one row per
session), are written when the session is created, and are available to every request for
the life of the session.

You define one struct type `T` and, usually, one function:

- **The struct declares the columns.** Each exported field maps to a column in your table
  via its `spanner:"..."` / `db:"..."` tag. The library reflects over `T` once at startup
  to derive the column list, writes rows from `T`'s field values, and scans rows straight
  back into `T` on every request — there is no hand-written decoder.

  ```go
  type MyData struct {
      TenantID string `spanner:"TenantId"`
      RoleID   string `spanner:"RoleId"`
  }
  ```

- **The resolver writes. It runs once, when the session is created.**
  A resolver is your function that produces the row to store:

  ```go
  func(ctx context.Context, txn *spanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) (*MyData, error)
  ```

  It executes **inside the same database transaction that inserts the session row** —
  at login, external authentication, or session regeneration — with the transaction
  available for consistent reads. The returned `*T` becomes the session's custom data
  row, committed atomically with the session (`nil, nil` means no row). If it returns an
  error, the whole login fails: no session, no cookies.

- **Reads are automatic, on every authenticated request.**
  Session validation fetches the custom row together with the session (one query) and
  scans it into a `*T`; handlers retrieve it with `auth.API().CustomData(ctx)` (returns
  `T`) or `sessioninfo.CustomDataFromCtx[*MyData](ctx)`.

**Declare the columns on the struct; resolve once at creation; read typed on every
request; update deliberately when mid-session state changes.** That is the whole mental
model — everything below is detail. The struct type and resolver are declared together
with the table name in one validated config unit (`NewSpannerCustomSessionData[T]` /
`NewPostgresCustomSessionData[T]`), attached to any storage constructor — password auth,
OIDC, or Preauth — via a typed option (`WithSpannerCustomSessionData` /
`WithPostgresCustomSessionData`). The session type is built for the same `T`
(`NewPasswordAuthFor[T]`, `NewOIDCAzureFor[T]`, `NewPreauthFor[T]`); at
construction the library verifies the storage's config was built for that `T`, so a
mismatch fails at startup, not at request time. Attaching a config built for one backend
to the other backend's storage does not compile.

One boundary before the details: this is **session data** — born with the session, reset
when the session is regenerated, gone when the session dies. Durable facts about the
*person* (profile fields, provisioning state) belong in a user table, not here — see
[docs/data-storage-guidance.md](docs/data-storage-guidance.md).

### The lifecycle at 1,000 feet

| Phase | What happens |
|---|---|
| **App start** | The config unit reflects over `T` and validates: `T` must be a struct with at least one exported persistable field, tags must pass identifier rules, `SessionId` is rejected as reserved, duplicate columns are an error. The session-type constructor verifies the storage config was built for the same `T`. Invalid config is a constructor **error** — nothing reaches runtime. |
| **Session creation** (login, external auth, regeneration, preauth) | The **resolver runs exactly once, inside the transaction that inserts the session row**. Its returned `*T` is written as the full custom data row with the implied `SessionId`. A resolver error aborts the transaction: **no session, no cookies, login fails**. Caller-supplied per-call data (where supported) is written the same way — atomically — and skips the resolver. No resolver and no per-call data ⇒ plain insert, no custom row. |
| **Every authenticated request** | Session validation runs **one query**: the session row `LEFT JOIN` your table. The columns are scanned into a fresh `*T` stored in the request context; a session with no custom row yields a zero-value `*T`. No second round-trip. |
| **Mid-session update** | `UpdateCustomSessionData(ctx, sessionID, func(data *T) error)` performs a transactional read-modify-write: your callback mutates the current row and the full row is written back. This is for *changing* session state mid-flight — never for initial population, which belongs in the creation transaction. |
| **Logout / expiry / cleanup** | Sessions are marked expired in place; your `ON DELETE CASCADE` foreign key removes the custom row whenever a session row is deleted. The library never deletes custom rows itself. |

Four questions this table answers: the resolver runs **at creation, once, in the insert
transaction**; reads are **typed and automatic, on every request**; a password change
**re-resolves fresh** (see Regeneration below); and misconfiguration fails **at
construction**, resolver failures **abort the login**, scan failures **fail the request**.

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

```go
type MyData struct {
    TenantID string `spanner:"TenantId"`
    RoleID   string `spanner:"RoleId"`
}

customCfg, err := sessionstorage.NewSpannerCustomSessionData(
    "SessionCustomData",
    func(ctx context.Context, txn *spanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) (*MyData, error) {
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

auth, err := session.NewPasswordAuthFor[MyData](
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
`WithPostgresCustomSessionData`) is identical in shape.

The released constructors (`NewPasswordAuth`, `NewOIDCAzure`, `NewPreauth`) are the
`NoCustomData` instantiations of the typed constructors — use them when the app has no
custom session data.

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
    func(ctx context.Context, txn *spanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) (*SessionClaims, error) {
        c := &SessionClaims{}
        if err := json.Unmarshal(req.Claims, c); err != nil {
            return nil, err
        }
        // Optionally JIT-provision an app user record here, keyed on the immutable oid,
        // using txn so provisioning commits atomically with the session.
        return c, nil
    },
)

oidcSession, err := session.NewOIDCAzureFor[SessionClaims](
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

It is available on all three session types: `PasswordAuthAPIFor`, `OIDCAzureAPIFor`,
and `PreauthAPIFor`.

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

##### Created and maintained by the CCC team.
