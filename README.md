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

You write two functions. The library runs them at opposite ends of the session's life:

- **The resolver writes. It runs once, when the session is created.**
  A resolver is your function that produces the values to store:

  ```go
  func(ctx context.Context, txn *spanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) ([]*sessioninfo.CustomData, error)
  ```

  It executes **inside the same database transaction that inserts the session row** —
  at login, external authentication, or session regeneration — with the transaction
  available for consistent reads. Whatever it returns becomes the session's custom data
  row, committed atomically with the session. If it returns an error, the whole login
  fails: no session, no cookies.

- **The decoder reads. It runs on every authenticated request.**
  A decoder is your function that converts the raw column values back into your typed
  struct:

  ```go
  func(rawColumns map[string]any) (T, error)
  ```

  Session validation fetches the custom row together with the session (one query) and
  hands the raw values to the decoder; handlers retrieve the result with
  `sessioninfo.CustomDataFromCtx[T](ctx)`.

**Resolve once at creation; decode on every request.** That is the whole mental model —
everything below is detail. Both functions are declared together with the table name and
column list in one validated config unit (`NewSpannerCustomSessionData` /
`NewPostgresCustomSessionData`), attached to any storage constructor — password auth,
OIDC, or Preauth — via a typed option (`WithSpannerCustomSessionData` /
`WithPostgresCustomSessionData`). Attaching a config built for one backend to the other
backend's storage does not compile.

One boundary before the details: this is **session data** — born with the session, reset
when the session is regenerated, gone when the session dies. Durable facts about the
*person* (profile fields, provisioning state) belong in a user table, not here — see
[docs/data-storage-guidance.md](docs/data-storage-guidance.md).

### The lifecycle at 1,000 feet

| Phase | What happens |
|---|---|
| **App start** | The config unit is built and validated: identifier rules on table/column names, `SessionId` rejected as reserved, duplicates deduped, decoder required. Invalid config is a constructor **error** — nothing reaches runtime. |
| **Session creation** (login, external auth, regeneration, preauth) | The **resolver runs exactly once, inside the transaction that inserts the session row**. It returns *(ColumnName, Value)* pairs which are written with the implied `SessionId`. A resolver error aborts the transaction: **no session, no cookies, login fails**. Caller-supplied per-call data (where supported) is written the same way — atomically — and skips the resolver. No resolver and no per-call data ⇒ plain insert, no custom row. |
| **Every authenticated request** | Session validation runs **one query**: the session row `LEFT JOIN` your table. The configured columns become a `map[string]any` handed to your **decoder**; the decoded value is stored in the request context. No second round-trip. |
| **Mid-session update** | `UpdateCustomSessionData` upserts the columns you pass (partial update, keyed on `SessionId`). This is for *changing* session state mid-flight — never for initial population, which belongs in the creation transaction. |
| **Logout / expiry / cleanup** | Sessions are marked expired in place; your `ON DELETE CASCADE` foreign key removes the custom row whenever a session row is deleted. The library never deletes custom rows itself. |

Four questions this table answers: the resolver runs **at creation, once, in the insert
transaction**; the decoder runs **on every request**; a password change **re-resolves
fresh** (see Regeneration below); and misconfiguration fails **at construction**, resolver
failures **abort the login**, decoder failures **fail the request**.

### Schema requirements

You create the table. The contract:

- A primary-key column named `SessionId` that is a **foreign key to the session table's
  primary key with `ON DELETE CASCADE`**.
- Never list `SessionId` in the configured columns — it is implied and reserved.
- Columns written by a resolver (or per-call data) must produce a complete valid row at
  insert time — plan `NOT NULL` constraints accordingly.

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

### The ColumnNames contract

The library never introspects your schema. The same identifiers must agree in two places:

1. **Your DDL** — the physical columns.
2. **The config unit** — `Columns` drives the `SELECT c.<name>` list on every read *and*
   provides the keys of the raw map handed to your decoder; the resolver's returned
   `ColumnName`s (and per-call data) become the INSERT columns.

Names are validated for shape at construction (letter/underscore start, ≤128 chars), but
whether they exist in your table is discovered by the database — a mismatch surfaces as a
query error.

### Configuration — username/password with a resolver

```go
type MyData struct {
    TenantID string
    RoleID   string
}

customCfg, err := sessionstorage.NewSpannerCustomSessionData(
    "SessionCustomData",
    func(m map[string]any) (MyData, error) {           // decoder: runs EVERY request
        d := MyData{}
        d.TenantID, _ = m["TenantId"].(string)          // values are nil when the
        d.RoleID, _ = m["RoleId"].(string)              // session has no custom row
        return d, nil
    },
    func(ctx context.Context, txn *spanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) ([]*sessioninfo.CustomData, error) {
        // resolver: runs ONCE per session creation, inside the insert transaction.
        // req carries Reason (Login | ExternalAuth | Regeneration | Preauth),
        // Username, UserID, Claims (OIDC), and any per-call CustomData.
        user, err := loadUser(ctx, txn, req.UserID)     // reads are txn-consistent
        if err != nil {
            return nil, err                             // aborts the login
        }
        return []*sessioninfo.CustomData{
            {ColumnName: "TenantId", Value: user.TenantID},
            {ColumnName: "RoleId", Value: user.RoleID},
        }, nil
    },
    "TenantId", "RoleId",
)
if err != nil { /* invalid identifier, reserved SessionId, nil decoder, ... */ }

auth, err := session.NewPasswordAuth(
    sessionstorage.NewSpannerPasswordAuth(client,
        sessionstorage.WithSpannerCustomSessionData(customCfg)),
    cookieKey,
    /* other options */
)
```

The resolver may be `nil`: session creation then performs a plain insert, and custom data
comes only from per-call values (below) or `UpdateCustomSessionData`. The Postgres mirror
(`NewPostgresCustomSessionData`, resolver over `pgx.Tx`,
`WithPostgresCustomSessionData`) is identical in shape.

### Configuration — Azure OIDC from verified claims

For OIDC logins the resolver receives the **complete raw verified ID-token claims** as
`req.Claims json.RawMessage` — the library does not curate a claims struct; unmarshal the
fields you need. A resolver error aborts the login before any cookie is written and the
user is redirected to the login page with the error's client message.

```go
type SessionClaims struct {
    Oid   string `json:"oid"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

customCfg, err := sessionstorage.NewSpannerCustomSessionData(
    "SessionClaimsData",
    func(m map[string]any) (SessionClaims, error) {
        c := SessionClaims{}
        c.Oid, _ = m["Oid"].(string)
        c.Name, _ = m["Name"].(string)
        c.Email, _ = m["Email"].(string)
        return c, nil
    },
    func(ctx context.Context, txn *spanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) ([]*sessioninfo.CustomData, error) {
        var c SessionClaims
        if err := json.Unmarshal(req.Claims, &c); err != nil {
            return nil, err
        }
        // Optionally JIT-provision an app user record here, keyed on the immutable oid,
        // using txn so provisioning commits atomically with the session.
        return []*sessioninfo.CustomData{
            {ColumnName: "Oid", Value: c.Oid},
            {ColumnName: "Name", Value: c.Name},
            {ColumnName: "Email", Value: c.Email},
        }, nil
    },
    "Oid", "Name", "Email",
)

oidcSession, err := session.NewOIDCAzure(
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
data, err := sessioninfo.CustomDataFromCtx[MyData](ctx)   // T must match the config's T
```

The decoder runs on every authenticated request, so a decoder error turns into a failed
request (401). Because the read is a `LEFT JOIN`, a session with **no** custom row still
loads — the decoder receives a map containing every configured column with `nil` values.
**Decoders must tolerate all-nil maps.**

### Per-call custom data

When the values come from the request rather than from config-time logic, pass them
directly at session creation — written atomically with the insert, and **the configured
resolver is skipped for that creation (per-call data wins)**:

```go
// Password auth, externally-authenticated users (e.g. admin impersonation):
sessionID, err := auth.API().StartAuthenticatedSession(ctx, w, username,
    &sessioninfo.CustomData{ColumnName: "TenantId", Value: tenantID},
    &sessioninfo.CustomData{ColumnName: "RoleId", Value: roleID},
)

// Preauth (trust-the-caller):
sessionID, err := preauth.API().Login(ctx, w, username,
    &sessioninfo.CustomData{ColumnName: "TenantId", Value: tenantID},
)
```

Per-call data requires a custom session data configuration on the storage (the config may
have a nil resolver). Passing data with no configuration attached is an error before
anything is inserted.

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
| Invalid table/column name, reserved `SessionId`, nil decoder | Error from the config constructor, at startup |
| Wrong-backend config on a storage constructor | Compile error |
| Resolver returns an error | Session creation aborts atomically: no session row, no custom row, no cookies; login fails (OIDC: redirect to login with the error's client message) |
| Per-call data with no config attached | Error before any insert |
| Column name not in your DDL | Database error from the creation transaction (aborts atomically) or from the per-request query |
| Decoder returns an error | The request fails (401) — every request, until fixed |
| Session has no custom row | Not a failure: decoder receives all-nil values (LEFT JOIN) |

##### Created and maintained by the CCC team.
