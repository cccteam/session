# Session

## Overview

The Session repository is designed to handle the management of user sessions, including authorization, storage, and expiration. It provides a framework for managing sessions across different databases and supports multiple login types.

## Features

- `Session Management`: Efficient handling of user session creation, storage, and expiration.
- `Database Support`: Seamless integration with multiple databases.
  - PostgreSQL
  - Google Cloud Spanner
- `Auth Sessions`: One session that every sign-in method can establish, with users, explicit identity links, pending confirmation and MFA. See the "Auth sessions (multiple sign-in methods)" section.
- `Sign-in methods` of the Auth session, each in its own package:
  - Username/Password (`session.PasswordSignIn`)
  - Microsoft Entra ID (Azure) OIDC (`session/azure`), with role synchronization from the token's roles and provider-initiated logout
  - Google Workspace OIDC (`session/google`), restricted to a Workspace's hosted domains, with role synchronization from Google Groups (see the "Google Workspace OIDC" section)
  - WorkOS SSO: built and tested, but under `internal` in v0.13.0 until its review; it returns to the public API in v0.13.1
- `Preauth`: trust-the-caller stepping-stone sessions (`session.NewPreauth`).
- `Legacy session types`: the single-method `PasswordAuth` and `OIDCAzure` of earlier releases, kept unchanged in `session/legacy` and deprecated. See the "Legacy session types" section and [docs/upgrading-to-v0.13.md](docs/upgrading-to-v0.13.md).
- `Custom Session Data`: App-defined data attached to each session, resolved atomically at session creation and available to every request. See the "Custom session data" section.
- `Custom User Data`: App-defined durable data attached to the user record — it survives logout, expiry, and regeneration, and dies with the user. See the "Custom user data" section.
- `OIDC User Anchor`: the legacy Azure type's durable user record, keyed by the immutable `(tid, oid)` claim pair; an Auth session's users are `SessionUsers` records for every method. See the "OIDC user anchor" section.
- `Login Refusal Codes`: A refused sign-in returns the browser to the login page with a code, never with text; the page maps the code to a sentence it holds itself. See the "Login refusal codes" section.

Every session type is generic over two data axes, custom session data and custom user
data: `Auth[SessionData, UserData, Tx]` (`Tx` is the storage's transaction type,
inferred from the store), the legacy `PasswordAuth[SessionData, UserData]` and
`OIDCAzure[SessionData, UserData]`, and `Preauth[SessionData]` (Preauth has no user
record, so no user-data axis). An application that uses neither axis instantiates with
the `NoCustomData` sentinel:
`session.NewAuth[session.NoCustomData, session.NoCustomData](store, cookieKey)`.

## Schema

The DDL for every table the library owns ships as golang-migrate files under
`schema/spanner/` and `schema/postgresql/`, one set per starting point: `migrations`
(the base set: sessions and users), `auth` (Auth sessions on the base set: the sessions'
users, identity links, auth events and pending sign-ins), `auth-from-oidc` (the upgrade
of a legacy Azure group to Auth), `impersonation`, and `oidc` (the legacy Azure type,
deprecated with it). Which sets a group applies is in "Storage and schema" below. The
`auth-from-oidc` set's backfill step is DML; the library's tests apply it with
db-initiator in one read-write transaction, so check that your migration runner
executes DML on Spanner.

**Time columns are the database's.** Every column that records when something happened
(a session's `CreatedAt`, `UpdatedAt` and `AuthenticatedAt`, an auth event's
`OccurredAt`, an impersonation record's `StartedAt` and `EndedAt`, an identity link's
`CreatedAt` and `LastUsedAt`, a pending sign-in's `CreatedAt` and `ConsumedAt`, the OIDC
user anchor's `CreatedAt` and `UpdatedAt`) is written with the database's time, never
the application's: Spanner's commit timestamp, PostgreSQL's transaction time (`now()`).
A host clock that runs ahead of the database's therefore cannot be refused, and the
rows one write stores carry one time. On Spanner the columns carry
`allow_commit_timestamp = true`: the shipped sets mark them (a `CommitTimestamps`
migration in each), and a table created by hand or named per group needs the same
option before a v0.13 driver writes to it, since a write to a column without it fails:

```sql
ALTER TABLE Sessions ALTER COLUMN CreatedAt SET OPTIONS (allow_commit_timestamp = true);
ALTER TABLE Sessions ALTER COLUMN UpdatedAt SET OPTIONS (allow_commit_timestamp = true);
```

A deadline (`ExpiresAt`) is the application's and is written as given. An auth event
the application hands the library (`sessioninfo.AuthEvent`) carries a zero `At` when it
happens now, and the database stamps it; an earlier event carries its time, stored as
given.

**PostgreSQL time columns are `timestamp with time zone`.** The driver writes `time.Time`
values as instants, which `timestamptz` stores faithfully whatever zone the host runs in.
Earlier revisions of the DDL declared `timestamp without time zone`, which keeps the wall
clock and drops the zone: a deployment on that type stays correct as long as every process
writing to it runs in UTC, and such a deployment does not need to migrate. To migrate
anyway, convert the columns and restart the application in the same window — pgx caches
the parameter types of its prepared statements, so a live pool keeps writing wall-clock
values (and fails one cached read per connection) until its connections are recycled:

```sql
-- Repeat for every time column created from the DDL (OIDCUsers CreatedAt and
-- UpdatedAt, the impersonation table's StartedAt/ExpiresAt/EndedAt).
-- 'UTC' names the zone the writing processes ran in.
ALTER TABLE "Sessions"
    ALTER COLUMN "CreatedAt" TYPE timestamptz USING "CreatedAt" AT TIME ZONE 'UTC',
    ALTER COLUMN "UpdatedAt" TYPE timestamptz USING "UpdatedAt" AT TIME ZONE 'UTC';
```

## Auth sessions (multiple sign-in methods)

`Auth[SessionData, UserData, Tx]` is one session that any registered sign-in method can
establish: password, Microsoft Entra ID (Azure), Google Workspace and WorkOS SSO. An
application mounts one cookie, one session table and one middleware chain, and every
session belongs to a **user**, a `SessionUsers` record, by its ID. The password
method checks the user's password; an external method produces a verified
**identity** that is linked to a user through the identities table, keyed by
`(method, connection, subject)` and **never by email**. `Tx` is the storage's
transaction type (`pgx.Tx` or `*spanner.ReadWriteTransaction`); `NewAuth` infers it from
the store, and the rules the application gives the `Auth` and its methods are typed to it.

Each redirect-based method is its own package (`session/azure`, `session/google`;
`session/workos` waits under `internal` until v0.13.1), built on the `session/signin`
contract and the shared `session/oidc` machinery; an application imports the packages of the methods it offers and registers
each with its `SignIn` function and `Config`.

| Method | Registration → handlers | Identity key (connection, subject) | Login parameters | Roles |
| --- | --- | --- | --- | --- |
| `password` | `PasswordSignIn(auth, options...)` → `*PasswordMethod`: `Login`, `ChangeUserPassword` | user ID | JSON `{"username", "password"}` | — |
| `azure` | `azure.SignIn(auth, name, rule, &azure.Config{...})` → `*azure.Method`: `Login`, `Callback`, `FrontChannelLogout` | (`tid`, `oid`) | `?returnUrl=` | `signin.RoleSync(manager)` or `signin.DisableRoleSync()` |
| `google` | `google.SignIn(auth, name, rule, &google.Config{...})` → `*google.Method`: `Login`, `Callback` | (`Connection`, `sub`) | `?returnUrl=` | `google.RoleSync(...)` or `google.DisableRoleSync()` |
| `workos` (internal until v0.13.1) | `workos.SignIn(auth, name, rule, &workos.Config{...})` → `*workos.Method`: `Login`, `Callback` | (`connection_id`, `idp_id`) | `?organization=` (required), `?returnUrl=` | never synchronized |

`name` identifies the registration on the `Auth` and must be unique there: one method
may be registered several times under different names, so one `Auth` offers two Entra
tenants as two registrations, each with its own configuration and rules. The password
registration is named `password`. `rule` is the application's own **account rule** for
an identity that is not linked to any user yet, and `nil` is the usual value: the
Entra and Google methods apply a **standard account rule** (`Config.Accounts`) to a
first sign-in (see "Storage and schema").

### Storage and schema

Each auth group owns six tables: sessions and users (the base migrations,
`schema/*/migrations`), identities, auth events and pending sign-ins (the auth
migrations, `schema/*/auth/migrations`, which also add `UserId`, `AuthenticatedAt`,
`ProviderSessionId` and `ProviderSessionIssuer` to the sessions table), and impersonations
(`schema/*/impersonation/migrations`) if you use it. Which set to apply depends on
where the group starts:

- **A new group**: the base set, then the auth set.
- **A group on the legacy password type** (`legacy.PasswordAuth`): the auth set only;
  the base set is already there. Nothing is backfilled: a session row from before the
  upgrade has no `UserId` and is refused as a session, so each person signs in once.
  To keep live sessions, set `UserId` from the users table by username first.
- **A group on the legacy Azure type** (`legacy.OIDCAzure`, the `oidc` set): the
  `schema/*/auth-from-oidc/migrations` set, at the cutover. It creates the users table,
  turns `OidcSid` into the nullable `ProviderSessionId`, adds the auth tables, and
  copies the OIDC user anchor's rows into users and Azure identities **under the same
  ids**, so a custom user data table keyed by the anchor keeps its rows once its foreign
  key points at the users table; live sessions take their user by username and lose
  their provider session id, so a later Entra logout cannot reach them. A group
  that never enabled the anchor skips the backfill statements and provisions each person
  at their first sign-in through its account rules. The anchor table is dropped in the
  release after the cutover, never in the same one, so a rollback to the legacy type
  stays possible until then.

[docs/upgrading-to-v0.13.md](docs/upgrading-to-v0.13.md) walks each starting point
through, code and schema.

The schema keeps its own integrity: a session belongs to an existing user (`UserId`,
null only for a role-principal impersonation), and deleting a user deletes its
sessions, their auth events and its identity links; your custom data tables cascade
from the session and user rows likewise. Sessions are marked expired, never deleted, by
the library: retention is the application's policy, and auth events last exactly as
long as their session rows.

An application whose groups are named applies the sets under the group's names and
tells the `Auth` them: `WithSessionTableName`, `WithUserTableName`,
`WithIdentitiesTableName` and `WithPendingSignInsTableName` on `NewAuth`, and
`NewAuthEventsTable(name)` / `NewImpersonationTable(name)` on the store. A table name
must be a plain identifier (a letter or underscore, then up to 127 letters, digits or
underscores): the store refuses any other, and the constructor reports it under the
option's name, so a name never reaches SQL unchecked. Name the users
table's unique index after the table as the shipped DDL does
(`<UsersTable>_NormalizedUsername_idx` on PostgreSQL, `<UsersTable>ByNormalizedUsername`
on Spanner): the drivers read a username conflict by that name. Build the
storage with `NewSpannerAuth` / `NewPostgresAuth`. The application's rules are given to
the `Auth` and to each method,
typed to the storage's transaction (`*spanner.ReadWriteTransaction` or `pgx.Tx`) so
they can read and write the application's own rows in the sign-in's transaction; a rule
written for the other driver's transaction does not compile. On Spanner a rule may run
more than once when the transaction retries,
so it must not have side effects outside it, and a row it writes with a mutation is
buffered until the commit, invisible to a later read in the same transaction: write with
DML what a later rule must read.

- The **sign-in policy** (`signin.Policy[Tx]`) is optional. Without one, a sign-in is
  decided by the library's own checks: the user exists and is enabled, the identity is
  linked or resolved, roles reconcile. An application with rules of its own sets them
  with `auth.SetSignInPolicy(rule)` after `NewAuth` and before serving; the rule
  answers for every method, and for a session the application starts for a user it
  authenticated itself (`StartAuthenticatedSession`), once the user is known, with
  `signin.Allow()`, `signin.Deny(code)` or
  `signin.RequireMFA(factors...)`. The factors are the methods the application's MFA
  step may record when it completes the sign-in (`"email-otp"`, `"totp"`): the pending
  status and the `PendingHook` report them, and `CompletePending` refuses any other;
  none accepts any.
- The **account rules** decide an identity's first sign-in: an identity that is not
  linked to any user yet. A linked identity signs in by its link and never consults
  them. Each Entra and Google registration declares a **standard rule** in
  `Config.Accounts`, which the library applies inside the sign-in's first transaction:
  - `signin.MembersOfDirectory` (the default): every member of the directory gets an
    account under their **sign-in name**, the user principal name on Entra and the
    verified email on Google. A user the application pre-created under that name,
    matched without regard to case, is linked instead: after a password confirmation
    when the user has a password, outright when the user has none and signs in through
    no other connection yet.
  - `signin.InvitedUsersOnly`: the same matching, and no provisioning; a person no user
    was created for is refused (`not_invited`). The application creates the users
    under their sign-in names, with or without a password, before they sign in.
  - `signin.OpenSignUp`: anyone who signs in gets an account under their sign-in name.
    It is for public applications and refused on a registration that serves one
    organization.

  Every standard rule writes nothing for a guest of the directory (an Entra B2B guest,
  refused with `guest_account`: a guest's preferred username is an address the
  directory did not verify), for a token asserting no application role when the method
  synchronizes roles (`no_roles`), or for an identity without a sign-in name
  (`no_email`). The tenant key on the link is the identity's connection: the Entra
  tenant id, the application's name for the Workspace.
- A registration's own **rule** (`azure.AccountRule`, `google.AccountRule`; required
  on WorkOS, which has no standard rule) is given to its `SignIn` function and runs
  first, for what the standard rule cannot know: it receives the method's own identity
  type (`*azure.Identity`, `*google.Identity`), decoded from the verified claims with
  the raw claims on it, and answers `signin.Reject(code)`, `signin.Link(userID,
  trusted)`, `signin.Provision(newUser, onProvisioned)`, `signin.Confirm(userID)` or
  `signin.Standard()`, which leaves the identity to the standard rule once the rule's
  own checks have passed; `signin.Tenant(key)` on any of the last four stores the
  application's tenant key on the link. A `Link` is the rule's own evidence, and the
  library asks for more when it can: a user who has a password must confirm with it
  (`Confirm`) unless the link is `trusted`; a user without a password cannot confirm,
  so an identity from another connection than the ones that user already signs in
  through is refused unless the link is `trusted`. Never choose the user by an email or
  another claim the provider does not verify.

A sign-in runs in two transactions, the same on Spanner and PostgreSQL:

1. **User resolution** (external methods): a linked identity is its user's;
   otherwise the account rules run, the registration's own first and then the standard
   one, and the outcome is applied: the link, or the new user, its link and the rows
   `Provision`'s `onProvisioned` writes. A link decision
   holds the user against another link decision until the transaction ends
   (PostgreSQL: a transaction-scoped advisory lock keyed by the user, which holds
   neither session inserts nor a rule's own reads of the user; Spanner: the
   transaction is serializable), so two racing sign-ins from two connections cannot
   both link a password-less user. A transaction the database ends to break a deadlock
   or a serialization failure runs once more.
2. **Decision and session**: the user is read (a disabled one is refused), the
   sign-in policy runs, and the session row is inserted with its auth events and custom
   session data.

Each transaction **commits unless a hook or the storage returns an error**. A `Reject`,
`Confirm`, `Deny` or `RequireMFA` answer is not an error: it commits the hook's own
writes (a record of a refused sign-up, an audit row) and writes no session. Because the
resolution has committed by the time the policy runs:

- the policy (and the custom session data resolver) **reads the user a sign-in just
  provisioned** and the rows `onProvisioned` wrote, on both backends;
- `req.User` (`*sessioninfo.SignInUser`) tells them which user was resolved and
  how: `Source` is `UserNamed` (password), `UserExistingLink`, `UserNewLink` or
  `UserProvisioned` (`req.User.Provisioned()`), with the link's `Tenant`;
- **a user a rule provisioned stays, linked, when the policy then denies the
  sign-in or holds it for MFA**; the next sign-in goes through the link and the policy
  decides again. Return `signin.Reject` from a custom rule when the user must not be
  created at all. A hook error rolls back its own transaction only: an `onProvisioned`
  failure leaves no user, while a policy error leaves a provisioned user in place.

```go
// The application's rules, typed to the store's transaction.
func signInPolicy(ctx context.Context, tx *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*signin.Decision, error) {
    if req.User.Provisioned() { // a first sign-in through SSO: the MFA step enrols the person
        return signin.RequireMFA("email-otp"), nil
    }

    return signin.Allow(), nil
}

// Optional: the application's own rule for an Entra identity's first sign-in. The
// standard rule in Config.Accounts handles the usual case; this one refuses what the
// standard rule cannot know and leaves the rest to it.
func entraAccountRule(ctx context.Context, tx *spanner.ReadWriteTransaction, identity *azure.Identity) (*signin.Resolution, error) {
    partner, ok, err := partnerOfTenant(ctx, tx, identity.TenantID) // the application's own rows
    if err != nil {
        return nil, err
    }
    if !ok {
        return signin.Reject("not_a_partner"), nil
    }

    return signin.Standard(signin.Tenant(partner)), nil
}

events, err := sessionstorage.NewAuthEventsTable("SessionAuthEvents")
store := sessionstorage.NewSpannerAuth(client, sessionstorage.WithAuthEvents(events))

auth, err := session.NewAuth[MyData, session.NoCustomData](store, cookieKey,
    session.WithCookieName("partner_auth"),
    session.WithIdentityLinked(notifyLinked), // called after every identity link
    session.WithPendingHook(onPending),       // called when a sign-in becomes pending
    session.WithPendingTimeout(10*time.Minute),
    session.WithPendingCookieName("auth-pending"),
)
auth.SetSignInPolicy(signInPolicy) // optional: without it the library's checks decide

// Register the sign-in methods before serving; each returns its own handlers.
password := session.PasswordSignIn(auth) // *session.PasswordMethod
sso := azure.SignIn(auth, "entra", entraAccountRule, &azure.Config{ // *azure.Method; nil leaves first sign-ins to Accounts alone
    IssuerURL: cfg.EntraIssuerURL, ClientID: cfg.EntraClientID, ClientSecret: cfg.EntraClientSecret,
    RedirectURL: cfg.SSORedirectURL, RoleSync: signin.DisableRoleSync(), LoginURL: "/login",
    Accounts: signin.InvitedUsersOnly, // the standard rule: pre-created users only
})
```

`NewAuth` refuses the OIDC-only storage features
(`WithOIDCUsers`, the custom user data login hook).

### Registering sign-in methods

A sign-in method is registered on the `Auth`, and its registration returns the method's
own handlers; routes are wired from that value. The handler is the proof of
registration: a method that was not registered has no handlers to wire, and each method
is its own type, so a handler exists only on the method it belongs to
(`FrontChannelLogout` only on `*azure.Method`). A registered method with no route is
harmless.

Registration is refused, with a panic, in one place, the way `http.ServeMux` refuses a
duplicate pattern: these are wiring mistakes, found when the application starts.

- **A registration name used twice** on one `Auth`, by the same method or another, or a
  registration without a name.
- **A registration name that cannot name its state cookie.** Each registration keeps its
  own state cookie, `OIDC-<name>`, so the name is letters, digits and hyphens
  (`lakeside-entra`): two registrations of one method, and logins with different
  providers in one browser, never read each other's state, and a callback completes only
  the login its own registration began.
- **A method registered once the `Auth` is in use**: after it has served a request
  through any of its handlers or middleware, or read its methods to check or hash a
  password through its API (`CreateSessionUser` before `PasswordSignIn(auth,
  HashAlgorithm(...))` would have hashed with the default). Register every method, then
  build the router and serve.
- **A registration without an account rule**: a WorkOS registration with a nil `rule`
  (WorkOS has no standard rule), or a registration naming a standard rule that does not
  exist.
- **A misconfigured method**: Azure or Google without its role sync slot, Google without
  its hosted domain or connection, open sign-up (`signin.OpenSignUp`) on a registration
  that serves one organization, cookie or session options passed to `PasswordSignIn`
  instead of `NewAuth`.

### Routes

```go
r.Use(auth.StartSession, auth.SetXSRFToken)
r.Get("/api/user/authenticated", auth.Authenticated())
r.Get("/api/user/sso/login", sso.Login())       // ?organization=…&returnUrl=…
r.Get("/api/user/sso/callback", sso.Callback())
r.Get("/api/user/pending", auth.Pending().Status())
r.Group(func(r chi.Router) {
    r.Use(auth.ValidateXSRFToken)
    r.Post("/api/user/session", password.Login())
    r.Post("/api/user/pending/confirm", auth.Pending().ConfirmWithPassword())
    r.Post("/api/user/pending/cancel", auth.Pending().Cancel())
    r.Post("/api/user/mfa", app.CompleteMFA) // checks the app's code, then auth.API().CompletePending
    r.Group(func(r chi.Router) {
        r.Use(auth.ValidateSession)
        r.Post("/api/user/logout", auth.Logout())
        r.Post("/api/user/password", password.ChangeUserPassword())
        // …protected routes
    })
})
```

The pending handlers and the API's pending methods read the pending identity
`StartSession` found, so they must run behind it; the POSTs belong behind
`ValidateXSRFToken` like the password login.

### The redirect and response contract

A sign-in ends in one of three ways. External methods answer with a redirect; the
password login and the pending handlers answer JSON. `<LoginURL>` is the method's
`Config.LoginURL` (default `/login`).

| Outcome | External `Callback()` | `password.Login()` |
| --- | --- | --- |
| Session established (new session ID) | `302 <returnUrl>` (default `/`) | `200 {"mfaIsRequired": false}` |
| Waits for the user's password | `302 <LoginURL>?pending=confirmation[&returnUrl=<path>]`, or the pending hook's URL | — |
| Waits for the application's MFA | `302 <LoginURL>?pending=mfa[&returnUrl=<path>]`, or the pending hook's URL | `200 {"mfaIsRequired": true[, "redirectUrl"]}` |
| Refused | `302 <LoginURL>?code=<code>` | `401 {"message", "code"}` (403 for a forbidden cause) |

- `returnUrl` is only ever a path in the application, in canonical form: one leading
  `/` (not `//` or `/\`), printable ASCII, no backslash anywhere (raw or `%5C`), no
  empty, `.` or `..` path segment (raw or percent-encoded), and a path made of RFC 3986
  path characters; its query and fragment pass through (`/settings/sso?test=done`,
  `/reports#x`). An external `Login()` whose `returnUrl` breaks any of these is refused
  with **400**, and the callback sanitizes it again, falling back to `/`. The callback
  writes the `Location` header with exactly that value. Percent-encode a non-ASCII path
  before passing it. A WorkOS `Login()` without `organization` is also 400, and its callback refuses a profile from another organization than the login requested (`organization_mismatch`).
- `pending` is the login page's routing marker. The page reads the pending identity from
  `Pending().Status()`: `200 {"reason", "email", "expiresAt", "returnUrl"[, "factors"]}`, `404` when
  there is none, `401 {"code": "pending_expired"}` once it has expired or been used.
- **Confirmation** (`reason` `confirmation`): the page asks for the existing user's
  password and posts `{"password"}` to `Pending().ConfirmWithPassword()`: `200
  {"mfaIsRequired": false}` (linked, the hook called, signed in; go to `returnUrl`),
  `200 {"mfaIsRequired": true}` (linked, but the policy wants MFA: the pending identity
  remains with reason `mfa`), `401` for a wrong password (the pending identity remains),
  `409` when the pending identity waits for MFA instead.
- **MFA** (`reason` `mfa`): the application runs its own step and calls
  `auth.API().CompletePending(ctx, w, sessioninfo.AuthEvent{Method: "email-otp"})`, which
  starts the session (the user is resolved afresh and must be the one it waited on, and
  the policy decides again with the step's events on the request, so a tenant disabled
  or switched to require SSO during the wait is honored: a `RequireMFA` the events
  satisfy proceeds, a `Deny` refuses, a `RequireMFA` for another factor holds again)
  and records the sign-in's events followed by the step's.
  The pending identity always names its user (`UserID`, `Username`), including one the
  sign-in has just provisioned, which exists by then.
- `Pending().Cancel()` discards the pending identity.
- **The pending hook** (`WithPendingHook`) runs when `password.Login()`, an external
  `Callback()` or `Pending().ConfirmWithPassword()` has just held a sign-in, after the
  pending identity is stored and its cookie set. It receives the
  `*sessioninfo.PendingIdentity` (reason, user, the identity with its email, expiry,
  return path), so the application can send its MFA code and choose the next page:

  ```go
  func onPending(ctx context.Context, w http.ResponseWriter, r *http.Request, p *sessioninfo.PendingIdentity) (string, error) {
      if p.Reason != sessioninfo.PendingMFA {
          return "", nil // the default: <LoginURL>?pending=confirmation
      }
      if err := mfa.SendCode(ctx, p.UserID.UUID); err != nil {
          return "", err // the pending identity is discarded and the sign-in fails
      }

      return "/user/mfa", nil
  }
  ```

  The callback redirects to the URL it returns, and the JSON handlers answer it as
  `"redirectUrl"`; an empty URL keeps the default. The hook may instead write the response
  itself, and nothing more is written. An error discards the pending identity and fails
  the sign-in (`?code=internal_error` on a redirect). The hook changes nothing about the
  pending identity (its cookie, its timeout; the session ID is regenerated when it
  completes). The URL is the application's own: never build it from request input. The
  `AuthAPI` methods never call the hook: `CompletePending` and
  `ConfirmPendingWithPassword` return a `*signin.PendingSignInError` instead.
- The codes are the `sessioninfo.LoginRefusalCode`s of the "Login refusal codes"
  section, including the resolver's and policy's own; text never travels.

### What a pending identity is

A pending identity is a verified identity waiting for its confirmation or MFA. It is a
row of the `SessionPendingSignIns` table (migration `000002` of the auth schema) holding
everything the sign-in carried: the identity and its claims, the registration it came
through, the user it waits on, the steps so far, the role names the method asserted, the
factors the policy accepts, the return path and when it expires. The browser holds only
the `auth-pending` cookie, encrypted and authenticated with the cookie key, carrying an
opaque 32-byte token; the row keeps the token's SHA-256. A pending identity is accepted
only while its row is live: not expired and not consumed. Completing, cancelling or
replacing it consumes the row by a conditional update, before the completion signs in,
so the token is single-use: of two completions racing on a copied cookie, one proceeds
and the other answers `pending_expired`. No session row exists until the sign-in
completes, so nothing of a pending identity ever validates as a session. Expired and
consumed rows stay for audit; delete them by `ExpiresAt` on your own schedule.

### Every session

- **The session ID is regenerated** at every sign-in, confirmation and MFA completion:
  the cookies are written only once the session row, its auth events and role
  synchronization have succeeded.
- **The user is loaded by `UserId` on every request.** `ValidateSession` refuses a
  session with no user or whose user is missing or disabled; the user is
  `sessioninfo.UserFromCtx(ctx)`. The session's user, authentication time and auth
  events are on the context's `*sessioninfo.SessionData`
  (`sessioninfo.DataFromCtx(ctx)`): `UserID`, `AuthenticatedAt`, `AuthEvents`.
- **Custom session data** is resolved in the transaction that inserts the session, after
  the user resolution has committed: the resolver reads the user (one just
  provisioned included) and the application's rows, and `req.User` says how the
  user was found. A pending identity has no session row, so it has no custom data.
- **Each session records how it was authenticated** in `SessionAuthEvents`: the sign-in
  method (with its connection and the IdP's `amr`), then any `link-confirmation` and MFA
  steps. `AuthAPI.StartAuthenticatedSession(ctx, w, userID, events)` starts a session the
  application authenticated itself, recording its events; it is decided like a login:
  the sign-in policy answers, a Deny refuses it and a RequireMFA holds it as a pending
  identity. No session start skips the policy; a support session is an impersonation.
- **Role synchronization** (Azure, Google) reconciles the roles of the user the
  identity resolved to, from the roles the provider asserted at sign-in, whenever such a
  sign-in establishes a session (including after a confirmation or MFA). A sign-in left
  with no recognized role is refused (`no_roles`) and its session expired.
- **Impersonation** works as on the other types. A user principal's session belongs to
  the impersonated user; a role principal's belongs to none. The session records an
  `impersonation` event whose connection is the actor.
- **User management is by ID**: `ChangeSessionUserPassword`, `SetSessionUserPassword`,
  `DeactivateSessionUser` and `DeleteSessionUser` destroy the user's sessions by
  `UserId`; `DeleteSessionUser` deletes its identity links with it; `UnlinkIdentity`
  refuses a user's last means of sign-in.
- **Provider-initiated (front-channel) logout** is keyed by the issuer of the token the
  sign-in verified and the provider's session id, since a provider's session id is
  unique only within its issuer: an Azure sign-in records the ID token's `sid` claim on
  its session row with that issuer (`ProviderSessionId`, `ProviderSessionIssuer`), a
  pending sign-in carries them to the session it completes, and a regenerated session
  keeps them. A registration declares the issuers its tokens may come from
  (`signin.Registration.Issuers`), and a round trip from any other issuer is refused
  (`internal_error`). `azure.Method.FrontChannelLogout()` ends every live session under
  the issuer the request names (`iss`), or the registration's only issuer when it names
  none, and the `sid` it names, impersonations started from it included (their records
  end `Logout`), answers 200, and 400 without a `sid`, with an `iss` the registration
  does not declare, or without an `iss` when the registration serves several issuers;
  it reads nothing from the browser, since Entra calls it in a frame, and a known `sid`
  under a declared issuer is its only credential. A
  session recorded with an id but no issuer (a legacy session the upgrade carried
  over) is out of its reach until the person signs in again. Register its route as the
  application's front-channel logout URL in Entra, outside `ValidateSession`. Sessions
  of the same user under another `sid`, or signed in by a method that reports no
  session id (password, Google, WorkOS), are not touched.

## Legacy session types

`PasswordAuth` and `OIDCAzure`, the single-method session types that predate `Auth`,
live in `session/legacy` and are deprecated: a new application uses `Auth` with
`PasswordSignIn` and `azure.SignIn`, one session for every sign-in method. Moving an
existing application is one mechanical edit, the import path and the qualifier of the
constructor, the handler interface, the API type and `WithLoginURL`:
`legacy.NewPasswordAuth`, `legacy.PasswordAuthHandlers`, `legacy.PasswordAuthAPI`,
`legacy.NewOIDCAzure`, `legacy.OIDCAzureHandlers`, `legacy.OIDCAzureAPI`,
`legacy.WithLoginURL`. The cookie and session options, the password options, the role
sync slot and `session.NoCustomData` stay in the root package. The storage pieces only
the legacy types use (`NewSpannerPasswordAuth`, `NewPostgresPassword`, `NewSpannerOIDC`,
`NewPostgresOIDC`, `WithOIDCUsers`, the custom user data login hook and the
`schema/*/oidc` migrations) carry the same deprecation and leave with them. Each legacy
type logs a warning once when it is constructed. The import edit, and the later move
to `Auth` with its schema upgrade, are in
[docs/upgrading-to-v0.13.md](docs/upgrading-to-v0.13.md).

## OIDC role synchronization

Role synchronization reconciles a user's application roles to the identity provider's
authorization signal on every OIDC login: role names sourced from the IdP are assigned
(where a role of that name exists), roles the user holds that are NOT among them are
removed, and the login is rejected unless at least one recognized role results. It is
designed for organizations that manage roles centrally in the directory. The role
names come from the provider's native mechanism — Azure delivers them in the token's
`roles` claim (App Role ↔ group assignments); Google has no such claim, so the Google
sign-in derives them from Google Groups membership at login (see the "Google Workspace
OIDC" section). See the `azure.SignIn`, `google.SignIn` and legacy `OIDCAzure` godoc for
the full semantics.

A membership is written where the role is held. A global role is held in the global
partition, and a domain role is held in every tenant domain, so one membership reaches
every tenant, the ones that exist today and the ones created later; the sync keeps no
list of tenants. A membership the directory does not name is removed wherever it is
held, a membership in one tenant domain included, so an application that writes its own
memberships (a tenant-specific role, say) runs with role synchronization disabled.

On an `Auth` session the slot is in the method's configuration, required for the two
methods that synchronize: `azure.Config.RoleSync` takes `signin.RoleSync(manager)` or
`signin.DisableRoleSync()`, and `google.Config.RoleSync` takes
`google.RoleSync(manager, groupPrefix, lookup)` or `google.DisableRoleSync()`.
`session.RoleSync` and `session.DisableRoleSync` are the same functions under the root
package's name. A registration without its slot is refused (see "Registering sign-in
methods").

```go
entra := azure.SignIn(auth, "azure", nil, &azure.Config{
    IssuerURL: issuerURL, ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
    RoleSync:  signin.RoleSync(userRoleManager), // or signin.DisableRoleSync()
})
```

The legacy `legacy.NewOIDCAzure` constructor takes the same slot as its second argument:

```go
// Enabled: reconcile the user's memberships to the token's roles at every login.
oidcSession, err := legacy.NewOIDCAzure[session.NoCustomData, session.NoCustomData](
    storage,
    session.RoleSync(userRoleManager),
    cookieKey, issuerURL, clientID, clientSecret, redirectURL,
)

// Disabled (application-managed roles, or no roles at all): no roles are read,
// written, or removed at login, and the at-least-one-role gate does not apply.
oidcSession, err := legacy.NewOIDCAzure[session.NoCustomData, session.NoCustomData](
    storage, session.DisableRoleSync(),
    cookieKey, issuerURL, clientID, clientSecret, redirectURL,
)
```

`session.UserRoleManager` is the role store surface the sync needs, and the access
package's `UserManager` satisfies it. Each method names where a membership is held with
an `accesstypes.PolicyScope`: `accesstypes.GlobalPolicyScope()` is the global partition
and `accesstypes.EveryDomainPolicyScope()` is every tenant domain, the two places the
sync writes. `UserRoles` called with no scopes lists every membership the user holds,
keyed by where each is held, which is how the sync finds a stale membership in one
tenant domain. `ResolveRole` finds the role a place holds under a name, matched without
regard to case, and answers it in the spelling the store holds: a Google group is an
email address and the groups lookup lowercases what it reads, so the directory names
`pilot` where the role file spelled `Pilot`, and the sync compares, adds and removes in
the store's spelling. A store that holds two roles differing only in case cannot answer
such a name, and the access library refuses to create the pair. `ResolveRole` errors must
be returned, never flattened to "role missing": the sync removes what the directory does
not name, so a swallowed store error would delete a valid membership on a transient
fault.

Migrating from the shape that took a domains provider (`session.RoleSync(manager,
domainsFn)` and `session.GoogleRoleSync(manager, domainsFn, ...)`): drop the provider,
since the sync no longer keeps a list of tenants, and give the manager the
`accesstypes.PolicyScope` signatures above. Older code that passed the manager straight
to `NewOIDCAzure` wraps it in `session.RoleSync(manager)`, and
`session.DisableUserRoleManagement()` becomes `session.DisableRoleSync()`, which also
disables the at-least-one-role login gate. `session.GoogleRoleSync` is now
`google.RoleSync`, in the `session/google` package.

## Google Workspace OIDC

Google Workspace sign-in is a method of the `Auth` session, registered with
`google.SignIn(auth, name, rule, &google.Config{...})` from the `session/google`
package (see "Registering sign-in methods" above). It is the counterpart of the Azure method: the
same session machinery, custom data axes and role-reconciliation semantics, built on
Google's identity model instead of Entra's. The mental-model difference that drives
every API difference: **an Entra app registration is an authorization surface** (App
Roles are declared on the app, assigned to groups, and delivered in the token's `roles`
claim), while **a Google OAuth client is authentication only** — the ID token says who
the user is (`email`, `sub`) and which Workspace org they belong to (`hd`), and nothing
about what they may do. Authorization signals therefore come from the directory itself
(Google Groups), fetched at login.

There is no `IssuerURL` setting — Google operates a single issuer for all orgs;
tenancy is the `hd` claim, not the issuer. The identity is linked to its user by the
registration's `Connection` and the `sub` claim: `sub` is globally unique among all
Google identities and never reused, and `Connection` is the application's own name for
the Workspace organization (`"lakeside"`), since Google puts no stable organization id
in the token and one Workspace answers for every domain it owns. The sign-in events
carry it too, so a policy tells Workspaces apart by connection and, within one, domains
apart by the identity's `HostedDomain`. **`Connection` is a key.** Changing it makes
every Google sign-in arrive as an unknown identity until the links are re-keyed:

```sql
UPDATE SessionIdentities SET "Connection" = 'new' WHERE "Method" = 'google' AND "Connection" = 'old'
```

The identity's sign-in name is the verified `email` claim (`email_verified` is
enforced), so the standard account rules (`Config.Accounts`) provision and match users
under it. Google has no `end_session_endpoint` and issues no `sid` claim, so there is no
Google-initiated logout: `Logout` destroys the local session only. The `RoleSync` slot
is `google.RoleSync(manager, groupPrefix, lookup)` or `google.DisableRoleSync()` (see
"The group naming convention").

### Restricting login to your organization

Two layers, one enforced by Google and one by this library:

1. **Internal OAuth consent screen** (Google-side): create the OAuth client in a Google
   Cloud project that belongs to your Workspace org and set the consent screen's user
   type to *Internal*. Google then refuses users outside the org (`org_internal`
   error) before they ever reach your callback.
2. **`HostedDomains`** (library-side, required): the Workspace's domains, one or
   more. The authorization request hints them to Google's account chooser (the domain
   when there is one, `*` for any Workspace account when there are several — UX only),
   and the verified ID token's `hd` claim must be one of them. A consumer user carries
   no `hd` claim at all, so the check fails closed. This is the trusted backstop even
   with an Internal consent screen in place.

### Skipping Google's account chooser

With one hosted domain, Google skips its account chooser when exactly one signed-in
account is in that domain; with several, the chooser appears whenever more than one
Workspace account is signed in. `Login` accepts `?login_hint=<email>` beside
`returnUrl` and passes it to Google as `login_hint`: Google picks that account when it
is signed in and pre-fills the sign-in form otherwise, so an identifier-first login
page (the person types their email, the page picks the registration) skips the chooser
whatever the registration's domain count. It is a hint and is never read back; the
identity comes from the verified token. A hint longer than 254 characters, or carrying
spaces or control characters, is refused with 400.

### The group naming convention

`google.RoleSync` derives candidate role names from group emails: a group whose local
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
lowercase names.

Membership is read at login through Google's Cloud Identity Groups API, with the
signing-in person's own access token. An access token is the credential that lets the
application call a Google API as that person. The library gets it by asking for one
extra OAuth scope, in addition to `openid`, `email` and `profile`:
`https://www.googleapis.com/auth/cloud-identity.groups.readonly`. A scope names one
permission the application asks the person for. The token is used for the lookup once
and never stored. No administrator credential is involved: no service account (a
Google user for software rather than a person), no domain-wide delegation (a
setting that lets such a user act as anyone in the organization), and no admin
role.

The last argument of `google.RoleSync` is a `google.GroupLookup`, which sets how far
the lookup reaches. It has two values:

- `google.DirectGroups()` (the default): one call. Only the groups the person is
  directly assigned to count, however the directory is nested (role groups should then
  hold people, not other groups — matching Entra's direct-only App Role resolution).
- `google.NestedGroups()`: the groups those groups are in count too, level by level,
  up to 10 levels. Each level is one round of calls to Google, so a deeply nested
  directory makes login slower. `DirectGroups` restores the one call.

`google.ParseGroupLookup(value)` reads the setting from configuration: `direct` or
`nested`, in any letter case, with surrounding space ignored. An empty value means
`DirectGroups`. Any other value is an error, so a misspelled setting stops the
application when it constructs its auth.

Google returns only the groups whose member list the person may view. A group whose
member list the person may not view is hidden: Google leaves it out, so that one
membership does not count. A hidden group never fails the lookup; the login goes ahead
with the groups Google returned. Two rules follow for your organization's groups:

- A group grants a role only if its *who can view members* setting includes the
  group's members.
- With `NestedGroups`, a hidden group hides everything above it, because the lookup
  cannot pass through it to the groups it is in.

A groups-lookup failure fails the login — the same posture as a role-store error.

## Login refusal codes

A refused redirect-based sign-in (an `Auth` session's Azure, Google or WorkOS method, or
the legacy `OIDCAzure`) returns the browser to the login page with the reason as a code,
never as text: `<LoginURL>?code=<code>`; the password login and the pending handlers
answer the same codes in JSON (see "The redirect and response contract"). The page maps
the code to a sentence it holds itself and shows nothing for a code it does not know, so
nothing that arrives in the URL is ever displayed. `LoginURL` is the method's
`Config.LoginURL` (the legacy type's `WithLoginURL`); its `Login()` and `Callback()`
redirect there, and `code` is the only query key a refusal writes.

The codes are typed constants in `sessioninfo` (`sessioninfo.LoginRefusalCode`), and the
table is the wire contract:

| Code | Constant | Produced when |
| --- | --- | --- |
| `internal_error` | `RefusedInternalError` | A fault the module does not classify: the authorization URL could not be built, the claims payload would not decode, the role store or session store failed, or a resolver error is neither a `LoginRefusal` nor a client message. |
| `login_refused` | `RefusedByApplication` | The application's custom session data resolver refused the login with an httpio client message and no code. The message goes to the log. |
| `no_oidc_cookie` | `RefusedNoOIDCCookie` | The callback arrived without the cookie the login route set. |
| `invalid_state` | `RefusedInvalidState` | The callback's `state` does not match the login this browser started. |
| `invalid_pkce` | `RefusedInvalidPKCE` | The login cookie carries no usable PKCE verifier. |
| `token_exchange_failed` | `RefusedTokenExchange` | The provider refused to exchange the authorization code for tokens. |
| `no_id_token` | `RefusedNoIDToken` | The token response carried no `id_token`. |
| `verify_id_token_failed` | `RefusedIDTokenVerification` | The ID token failed signature, issuer, audience, or expiry verification. |
| `parse_claims_failed` | `RefusedClaimsParse` | The verified ID token's claims would not decode. |
| `not_workspace_member` | `RefusedNotWorkspaceMember` | Google: the user is outside the Workspace domain logins are restricted to. |
| `email_not_verified` | `RefusedEmailNotVerified` | Google: the user's email address is not verified. |
| `organization_mismatch` | `RefusedOrganizationMismatch` | WorkOS: the profile belongs to another organization than the login requested. |
| `no_roles` | `RefusedNoRoles` | Role synchronization left the person with no recognized role, or a standard account rule saw a token asserting no application role and wrote nothing. |
| `no_email_claim` | `RefusedNoEmailClaim` | Google: the ID token carries no `email` claim. |
| `identity_rejected` | `RefusedIdentityRejected` | Auth: the account rule rejected the identity (its own code wins when it sets one), linked a user that has a password without confirmation, a password-less user who signs in through another connection was matched or linked without trust, or the identity resolved to another user than it waited on. |
| `not_invited` | `RefusedNotInvited` | Auth: under the invited-users-only account rule, no user was created for the identity's sign-in name. |
| `guest_account` | `RefusedGuestAccount` | Auth: the identity is a guest of its directory (an Entra B2B guest), which the standard account rules refuse. |
| `policy_denied` | `RefusedByPolicy` | Auth: the sign-in policy denied the sign-in (its own code wins when it sets one). |
| `user_disabled` | `RefusedUserDisabled` | Auth: the sign-in resolved to a disabled user. |
| `pending_expired` | `RefusedPendingExpired` | Auth: a confirmation or MFA step arrived after its pending identity expired or was used. |
| `no_email` | `RefusedNoEmail` | The external identity carries no email address where one is required: an application's rule asks for one, or a standard account rule found no sign-in name to use as the username. |

**The resolver rule.** A custom session data resolver's error decides the code by its
shape. A `sessioninfo.LoginRefusal` (`sessioninfo.NewLoginRefusal(code, cause)`) answers
its code, and the code may be the application's own — `LoginRefusalCode("not_provisioned")`
— as long as the application's login page holds text for it. An httpio client message with
no code answers `login_refused`, and its text stays in the log. Any other error answers
`internal_error`. `LoginRefusal` unwraps to its cause, so the log handler still sees the
client message's status and `errors.Is` still matches the cause.

```go
func resolve(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*SessionClaims, error) {
    member, err := lookUpMember(ctx, txn, req.Username)
    if err != nil {
        return nil, errors.Wrap(err, "lookUpMember()") // internal_error
    }
    if member == nil {
        return nil, sessioninfo.NewLoginRefusal("not_provisioned", httpio.NewForbiddenMessage("member is not provisioned"))
    }

    return &SessionClaims{...}, nil
}
```

**The page authors all text.** A login page reads `code` and renders the sentence it holds
for it; it never renders the parameter. Angular applications get the mapping from
`@cccteam/resource-angular`: `LOGIN_MESSAGES` holds a sentence for every code above,
`UiCoreService.loginMessage(code)` looks one up (empty for an unknown code) and
`publishLoginError(code)` raises it as a notification, and `provideLoginMessages({...})` in
the application's providers adds the application's own codes or rewords a default.

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
  If it returns an error, the login fails: no session, no cookies. For an `Auth`
  sign-in it runs after the user resolution has committed (see "Auth sessions"); a
  pending identity has no session row, so nothing is resolved until it completes.

- **Every request reads it — automatically.** Session validation fetches the custom
  row together with the session (a single `LEFT JOIN` query) and your handlers get a
  typed `T` back with `auth.API().CustomData(ctx)`. No second round-trip, no manual
  decoding.

- **Mid-session changes are deliberate.** `UpdateCustomSessionData` is a transactional
  read-modify-write: a typed callback mutates the current row and the full row is
  written back. It exists for *changing* state mid-flight (a tenant switcher) — never
  for initial population.

- **Everything is checked at startup.** The session type is generic over the same
  struct (`Auth[MyData, ...]`), and construction verifies the storage's custom data
  configuration was built for it. Misconfiguration is a boot failure, not a request-time
  surprise; a resolver typed to the other driver's transaction does not compile.

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

### Configuration — Auth

An `Auth` store takes one custom session data configuration. The struct, the table
name and the resolver are declared together with `NewCustomSessionData`; `T` and the
store's transaction type are inferred from the resolver, and the transaction type
selects the driver and the tags that name the columns (`db:"..."` for PostgreSQL,
`spanner:"..."` for Spanner). The configuration is attached with the store's
`WithCustomSessionData`, which takes only a configuration typed to that store's
transaction: one built for the other driver does not compile there. The session type is
built for the same `T`:

```go
type MyData struct {
    TenantID string `db:"TenantId"`
    RoleID   string `db:"RoleId"`
}

sessionData, err := sessionstorage.NewCustomSessionData(
    "SessionCustomData",
    func(ctx context.Context, tx pgx.Tx, req *sessioninfo.NewSessionRequest) (*MyData, error) {
        // Runs ONCE per session creation, inside the transaction that inserts the
        // session, after the user resolution: req.UserID is the user (one the
        // resolver just provisioned included) and req.User says how it was found.
        member, err := loadMember(ctx, tx, req.UserID)   // reads are tx-consistent
        if err != nil {
            return nil, err                             // aborts the sign-in
        }
        return &MyData{TenantID: member.TenantID, RoleID: member.RoleID}, nil
    },
)
if err != nil { /* non-struct T, no persistable fields, invalid identifier, reserved SessionId, ... */ }

store := sessionstorage.NewPostgresAuth(pool, sessionstorage.WithAuthEvents(events)).
    WithCustomSessionData(sessionData)
auth, err := session.NewAuth[MyData, session.NoCustomData](store, cookieKey, signInPolicy)
```

With a `nil` resolver, name both types: `NewCustomSessionData[MyData, pgx.Tx]("SessionCustomData", nil)`;
session creation then performs a plain insert, and custom data comes only from per-call
values (below) or `UpdateCustomSessionData`. A Spanner store takes a resolver over
`*spanner.ReadWriteTransaction` and reads `spanner:"..."` tags; a struct tagged for both
drivers serves either. The per-driver pair (`NewSpannerCustomSessionData`,
`NewPostgresCustomSessionData` and their options) serves the legacy stores below.

### Configuration — legacy username/password with a resolver

For the legacy stores, the struct and resolver are declared together with the table
name in one validated config unit per driver, attached to the storage via a typed
option, and the session type is built for the same `T`:

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

auth, err := legacy.NewPasswordAuth[MyData, session.NoCustomData](
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

### Configuration — legacy Azure OIDC from verified claims

For OIDC logins the resolver receives the **complete raw verified ID-token claims** as
`req.Claims json.RawMessage` — the library does not curate a claims struct; unmarshal the
fields you need. A resolver error aborts the login before any cookie is written and the
user is redirected to the login page with a refusal code: the code of a
`sessioninfo.LoginRefusal` the resolver returned, else `login_refused` for a client
message, else `internal_error` (see "Login refusal codes").

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

oidcSession, err := legacy.NewOIDCAzure[SessionClaims, session.NoCustomData](
    sessionstorage.NewSpannerOIDC(client, sessionstorage.WithSpannerCustomSessionData(customCfg)),
    session.RoleSync(userRoleManager), // see "OIDC role synchronization"
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
// Auth: a session the application authenticated itself, by user ID, recording how
// (decided like a login: the sign-in policy answers when one is set):
sessionID, err := auth.API().StartAuthenticatedSession(ctx, w, userID,
    []sessioninfo.AuthEvent{{Method: "api-key"}},
    &MyData{TenantID: tenantID, RoleID: roleID},
)

// Legacy password auth, externally-authenticated users (e.g. admin impersonation):
sessionID, err := passwordAuth.API().StartAuthenticatedSession(ctx, w, username,
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

It is available on every session API: `AuthAPI`, `PreauthAPI` and the legacy
`PasswordAuthAPI` and `OIDCAzureAPI`.

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
patching them (`DestroyUserSessions` on `Auth`, `DestroyAllUserSessions` on the legacy
types); the next login re-resolves.

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
| Resolver returns an error | Session creation aborts atomically: no session row, no custom row, no cookies; login fails (OIDC: redirect to the login page with a refusal code, see "Login refusal codes") |
| Per-call data with no config attached, or more than one per-call value | Error before any insert |
| Column name not in your DDL | Database error from the creation transaction (aborts atomically) or from the per-request query |
| `NULL` column scanned into a non-nullable field | The request fails (401) — map nullable columns to nullable Go types |
| `UpdateCustomSessionData` callback returns an error | Transaction aborts; nothing written |
| `UpdateCustomSessionData` on an expired session | Rejected (bad request); the row is not written |
| Session has no custom row | Not a failure: reads yield a zero-value `T` (LEFT JOIN) |

## OIDC user anchor (legacy Azure type)

An `Auth` session needs no anchor: its users are `SessionUsers` records for every
method, and an external identity links to its user by `(method, connection, subject)`
(see "Auth sessions"). The anchor serves the legacy `OIDCAzure` type and is deprecated
with it; the `auth-from-oidc` upgrade set carries its rows into users and Azure
identities under the same ids (see "Storage and schema").

The OIDC user anchor is an optional, library-managed **durable user record for the
legacy Azure OIDC type** — the OIDC counterpart of password auth's `SessionUsers` table. Password auth
always has a stable, rename-safe user key (`SessionUsers.Id`); OIDC historically had
none, which pushed apps toward keying durable data on the username — a mutable,
recyclable identifier (see AP-1 in
[docs/data-storage-guidance.md](docs/data-storage-guidance.md)). The anchor closes that
gap.

How it works:

- **One row per directory identity, keyed by the provider's immutable identity.** The
  `OIDCUsers` table (ship the `schema/*/oidc/migrations` migration) keys each user by
  the immutable `(tid, oid)` claim pair — the only rename-proof, recycle-proof identity
  Azure gives you (`oid` is only unique within a tenant) — under a surrogate UUID
  primary key. `Username` (`preferred_username`) is a mutable *attribute* on the row,
  never part of the key.
- **Maintained just-in-time, atomically with login.** Enable it with
  `sessionstorage.WithOIDCUsers()` on the OIDC storage constructor. Inside every
  session-insert transaction the library upserts the row: first login provisions it; a
  login after an IdP rename updates `Username` in place (continuity preserved — no
  orphaned record, no data inherited by a future holder of the old name); every login
  touches `UpdatedAt`. A missing key claim (`tid` or `oid`) aborts the login before any
  row or cookie exists.
- **The durable key flows into your hooks.** `NewSessionRequest.UserID` carries the
  anchor record's ID into the custom session data resolver (copy it into a session
  column to reach the user record from any request without a lookup) and into the
  custom user data hook (below).
- **Read it when you need it.** `oidcSession.API().OIDCUser(ctx, id)` and
  `OIDCUserByKey(ctx, tid, oid)` return the record. Identity comparison in OIDC is
  always the provider's immutable key — never the username.

```go
storage := sessionstorage.NewSpannerOIDC(client,
    sessionstorage.WithOIDCUsers(),
    /* custom data options */
)
```

`WithOIDCUsers()` enables *the anchor*. The table name defaults to `OIDCUsers`
(`session.WithOIDCUserTableName` overrides it). The anchor is OIDC-only: enabling it on
password-auth or preauth storage is a construction error. It is required for custom
user data on OIDC storage.

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
- **The write path depends on the auth mode**, because the modes learn about users
  differently:
  - **Auth**: initial data is **per-call on `CreateSessionUser`**, written atomically
    with the user insert, or written by a custom account rule's `signin.Provision` hook
    in the sign-in's transaction for a user it provisions. There is no login hook: an
    identity's claims reach the rule, which decides what to keep.
  - **Legacy password auth**: users are created explicitly, so initial data is **per-call on
    `CreateSessionUser`**, written atomically with the user insert. There is no
    login-time hook — password logins carry no claims.
  - **Legacy Azure OIDC**: users just *arrive*, known only by their verified claims, so the
    config carries a **login hook** that runs inside every OIDC session-insert
    transaction, after the anchor upsert (requires the OIDC user anchor).
  - **Preauth**: unsupported — there is no user record to anchor durable data to
    (construction error if configured).

### Schema requirements

Identical to the session-data contract with one substitution: the primary-key column is
named `UserId` and is a **foreign key with `ON DELETE CASCADE`** to `SessionUsers(Id)`
(`Auth` and the legacy password type) or `OIDCUsers(Id)` (the legacy Azure type). Never tag a field `UserId` — it is implied
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

### Configuration — Auth

An `Auth` store takes one custom user data configuration, which fits either driver:
`NewCustomUserData` validates the columns `U`'s `db:"..."` tags name for PostgreSQL and
its `spanner:"..."` tags name for Spanner, and the store's `WithCustomUserData` attaches
it. The session type is built for the same `U`:

```go
type UserData struct {
    Locale string `db:"Locale" spanner:"Locale"`
    Theme  string `db:"Theme" spanner:"Theme"`
}

userData, err := sessionstorage.NewCustomUserData[UserData]("UserCustomData")

store := sessionstorage.NewPostgresAuth(pool, sessionstorage.WithAuthEvents(events)).
    WithCustomSessionData(sessionData).
    WithCustomUserData(userData)
auth, err := session.NewAuth[MyData, UserData](store, cookieKey, signInPolicy)

// Create: initial data lands atomically with the user insert (at most one value —
// it is the complete row). Omit it for a plain insert (reads yield zero-value U).
id, err := auth.API().CreateSessionUser(ctx, req, &UserData{Locale: "en-AU"})

// Read: on demand, by user ID — never from the session context.
u, err := auth.API().CustomUserData(ctx, userID)

// Update: transactional read-modify-write — mutate the current row (zero-value U
// when none) and the full row is written back.
err = auth.API().UpdateCustomUserData(ctx, userID, func(d *UserData) error {
    d.Theme = "dark"
    return nil
})
```

### Configuration — legacy password auth

```go
type UserData struct {
    Locale string `spanner:"Locale"`
    Theme  string `spanner:"Theme"`
}

userCfg, err := sessionstorage.NewSpannerCustomUserData[UserData]("UserCustomData", nil)

auth, err := legacy.NewPasswordAuth[MyData, UserData](
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

### Configuration — legacy OIDC with a login hook

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

oidcSession, err := legacy.NewOIDCAzure[SessionClaims, UserProfile](
    sessionstorage.NewSpannerOIDC(client,
        sessionstorage.WithOIDCUsers(), // the anchor is required for OIDC user data
        sessionstorage.WithSpannerCustomSessionData(sessCfg),
        sessionstorage.WithSpannerCustomUserData(userCfg)),
    session.RoleSync(userRoleManager),
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
role chosen for the session). Every session type supports both — `Auth`, `Preauth`
and the legacy types — through the same `ImpersonationRequest` on each `API()`.

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

auth, err := session.NewAuth[MyData, session.NoCustomData](
    sessionstorage.NewSpannerAuth(client,
        sessionstorage.WithAuthEvents(events),
        sessionstorage.WithImpersonation(imp)).
        WithCustomSessionData(sessionData),
    cookieKey, signInPolicy,
    session.WithImpersonationTimeout(time.Hour),        // hard cap; default one hour
    session.WithImpersonationAudit(func(ctx context.Context, e sessioninfo.ImpersonationEvent) error {
        return auditTrail.Record(ctx, e)                 // Started, Ended, IdentityOperationBlocked
    }),
)
```

The same `WithImpersonation` option and `WithImpersonationTimeout` /
`WithImpersonationAudit` session options apply to `NewPreauth` and the legacy
constructors (`sessionstorage.NewSpannerPasswordAuth(client, sessionstorage.WithImpersonation(imp))`).
Without `WithImpersonation` nothing changes: no session is ever impersonated and the
impersonation APIs return a configuration error.

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

// An administrator of the admin application works the partner portal under a role.
id, err := auth.API().StartImpersonatedSession(ctx, w, &session.ImpersonationRequest{
    Actor:      "alice@example.com",
    ActorRealm: "admin-portal",
    Principal:  accesstypes.RolePrincipal("PartnerViewer"),
}, &MyData{PartnerID: partnerID}) // custom session data rides along as usual

// A user of this application acts under a narrower role for a while — their own
// session, narrowed. The actor is local: no realm, and their own session as the source.
// The call arrives on their validated session, so SourceSessionID may be omitted: it
// defaults to that session, and Actor must be that session's user.
info := sessioninfo.FromCtx(ctx)
id, err := auth.API().StartImpersonatedSession(ctx, w, &session.ImpersonationRequest{
    Actor:     info.Username,
    Principal: accesstypes.RolePrincipal("Auditor"),
})
```

The session row and the record are written in one transaction; the cookie is set only
after the `Started` event has been delivered (a failing audit hook destroys the session
and fails the call). Refused everywhere: a missing actor or principal, a caller that is
itself an impersonated session (no chaining), and a local actor whose `SourceSessionID`
is missing or is not their own live session here.

When the call arrives on a validated session of this application (the context has passed
`ValidateSession`), the request is bound to that session: `Actor` must be its user,
`SourceSessionID` must be it (and defaults to it when omitted), and `ActorRealm` must be
empty — an actor logged in here is local. The binding keeps a caller from minting a
session as another user by naming them and one of their session IDs, which appear in
logs, spans and `ActiveImpersonations`. A call with no session in its context (a
server-to-server handoff) is taken at its word, so its handler must authenticate the
caller. *Who may impersonate whom* is the application's guard — the library records what
happened.

#### Identity by session type

A role principal's session is always the actor's: nobody's identity is borrowed. What a
**user** principal resolves to depends on what the session type knows about users:

| Session type | User principal becomes | User ID | Refused |
| --- | --- | --- | --- |
| Auth | The `SessionUsers` record's username; the session belongs to that user and records an `impersonation` auth event naming the actor | The record's ID | A missing or disabled user |
| Legacy password auth | The `SessionUsers` record's username | The record's ID | A missing or disabled user |
| Preauth | The name as given | Zero | — (trust-the-caller, as `Login` is) |
| Legacy OIDC Azure | The name as given (what a login would take from the token) | Zero | — |

On an `Auth` session an impersonation carries no identity of its own: no identity is
linked, no roles are synchronized, and the custom session data resolver receives
`ReasonImpersonation` with no claims. A provider-initiated logout reaches it through the
session it was started from: `azure.Method.FrontChannelLogout()` ends the impersonations
started from a session under the `sid` it names (their records end `Logout`) and no
other (see "Every session").

An impersonated session of the legacy `OIDCAzure` type authenticates no ID token: no OIDC user anchor is upserted,
no roles are synchronized, and the configured custom session data resolver receives
`ReasonImpersonation` with no claims. The row carries no identity provider session ID,
so an identity provider logout cannot name it directly — but `FrontChannelLogout` expires
every live session carrying the *username* of the session the provider named. A provider
logout of `bob@partner.org` therefore also ends every user-principal impersonation of bob
and any foreign actor's role session borrowing bob's name. The logout itself does not end
those sessions' records; the next request on one is refused and ends its record
`Expired`. Otherwise it ends by its hard cap, idle expiry,
`Logout`, `EndImpersonation`, `DestroyImpersonatedSession`, or
`DestroyImpersonatedSessions`.

#### Local and foreign actors

`ActorRealm` says where the actor was authenticated, and it decides what the actor's name
means in this application's session table:

| | Local actor (`ActorRealm` empty) | Foreign actor (`ActorRealm` set) |
| --- | --- | --- |
| Who | A user of this application, logged in here | Authenticated by another application or IdP |
| `SourceSessionID` | Required and verified: the actor's own live, non-impersonated session here, carrying their username. Defaults to the request's own session when the call arrives on one | Optional; the session in the source application, for correlation |
| A role principal's session | The actor's own session, narrowed to the role | A session under a borrowed name |
| Kept alive | The source session's activity is refreshed with the impersonated session's, so `EndImpersonation` can return to it | — |
| Deactivating or renaming the user named `Actor` | Includes the role session and every impersonation the actor holds (see *One name, one user*) | Never touches the role session |

Minting an impersonated session in the same application the actor is logged into
replaces the browser's session cookie — which is why the source session is verified,
kept alive, and returned to.

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

By default a session's principal is its user, or the impersonation record's principal,
and for almost every application that is the end of the story: put role membership in
the permission store, check with `ForUser`, and a role change is enforced on the user's
next request. `WithPrincipalResolver` exists for the narrow case where a session's
subject genuinely is not a user. The resolver runs inside session validation, with the
session, its custom data and its impersonation record in the context, and returns the
principal `PrincipalFromCtx` reports for the request.

**The resolver chooses *which subject*, never *which grants*.** Grants always come from
the permission store at check time. The moment a resolver reads role membership from
somewhere that was copied at login, the application has built a cache of its
authorization model with a lifetime of one session, and no amount of live grant checking
repairs that.

#### Intended uses

- **Machine and API-key sessions.** The caller is a service, not a person; the subject is
  the service's role, decided from the credential the session was established with.
- **Membership that lives outside the permission store and is read live.** The resolver
  asks the external system on each request (or through a cache with a deliberate,
  short TTL that the application owns and documents). Staleness is bounded by that TTL,
  not by the session.

```go
// A service session acts as the role bound to its API key. The key-to-role binding is
// read on every request, so revoking or re-binding the key takes effect immediately.
auth, err := session.NewPreauth[APIKeySession](storage, cookieKey,
    session.WithPrincipalResolver(func(ctx context.Context) (accesstypes.Principal, error) {
        data, err := sessioninfo.CustomDataFromCtx[*APIKeySession](ctx)
        if err != nil {
            return accesstypes.Principal{}, err
        }
        role, err := keys.RoleForKey(ctx, data.KeyID) // live lookup, not a stored copy
        if err != nil {
            return accesstypes.Principal{}, err
        }

        return accesstypes.RolePrincipal(role), nil
    }),
)
```

#### Not for this

- **A role snapshotted into custom session data at login.** `RolePrincipal(data.RoleID)`
  where `RoleID` was resolved when the session was created is the anti-pattern this
  section exists to name. The user keeps the old role until they log in again; an
  administrator's change is silently ignored for the life of every open session. The fix
  is not a resolver — it is moving membership into the permission store
  (`AddUserRoles` / `DeleteUserRoles`) and letting the default user principal do its job.
- **"The user picked a role for this session."** That is a deliberate, time-capped act
  by an actor, which is what the impersonation record is for: establish a role-principal
  impersonation with the user as actor and you get evidence, a hard cap, listing and
  revocation. A resolver gives you none of those.
- **Avoiding a permission-store write.** If the only reason to reach for the resolver is
  that membership is stored somewhere else and nobody wants to move it, move it.

#### Mechanics

- The choice is made per request at validation and never stored; nothing changes in the
  schema and no impersonation record is written.
- The resolver runs for ordinary sessions and for user-principal impersonations — an
  impersonated user's session acts as that user's session would. A role-principal
  impersonation already names its subject and skips the resolver.
- Returning the zero `Principal` keeps the default. An error fails the request as a
  server error, not an unauthorized one: the session is valid; the application could not
  decide what it acts as.
- When the resolver changes the principal, the request's log entry and trace span carry
  `principal.kind` and `principal` (`sessioninfo.AttrPrincipalKind`,
  `sessioninfo.AttrPrincipal`); unchanged requests carry nothing extra.

### Evidence

Everything an impersonated session touches names the actor and the principal:

| Evidence | Where |
| --- | --- |
| The record (actor, realm, source session, principal, mask, reason, started/expires/ended, end reason) | The impersonation table, durable |
| `impersonation.actor`, `.actor_realm`, `.principal_kind`, `.principal`, `.mask`, `.session_id`, `.source_session_id` | The request-level log entry and every line logged within the request (constants in `sessioninfo`) |
| `principal.kind`, `principal` — when a `WithPrincipalResolver` changed the request's subject | The request-level log entry and every line logged within the request |
| `Started` / `Ended` / `IdentityOperationBlocked` / `WriteBlocked` events | Structured log lines, span events (`impersonation.Started`, …) on the current trace span, plus the `WithImpersonationAudit` hook |
| `enduser.id` (the session's username), the same `impersonation.*` attributes, and `principal.*` when a resolver changed the subject | The request's server span from the `ValidateSession` middleware (the caller's current span from `ValidateSessionAPI`), impersonation attributes set before any refusal so a refused request's trace still names the actor; the establishing call's own span on the source side |
| The establishing call's own log entry | The source application's request log |
| `impersonation` object in the `Authenticated()` response | For the frontend to banner the session and render read-only affordances |

### Lifecycle and guards

- **Hard cap.** `ExpiresAt` is fixed at establishment (`WithImpersonationTimeout`,
  default one hour, shortened per call by `MaxDuration`); idle renewal never extends past
  it. The idle session timeout applies independently.
- **Ending.** Logout, the hard cap, idle expiry, `EndImpersonation`, and
  `DestroyUserSessions` (`DestroyAllUserSessions` on the legacy types) all end the
  record with a reason (`Logout`, `Expired`, `Released`, `Revoked`); an `Auth` session's
  Azure front-channel logout ends the records of the impersonations it reaches `Logout`;
  the legacy `OIDCAzure` `FrontChannelLogout` expires the row, and the record ends
  `Expired` on the session's next request. `API().DestroyImpersonatedSessions(ctx, actor)`, on every
  session type, is the offboarding and incident tool: it expires every live impersonated
  session an actor established.
- **Returning to self.** `EndImpersonation` (a handler on every session type, routed
  inside the validated group; `API().EndImpersonation(ctx, w)` beside it) ends the
  impersonated session `Released` and, for a local actor whose own session is still live,
  not itself impersonated, and still theirs, gives the response that session's cookies:
  the actor is back in their own session without logging in. The body says whether that
  happened (`{"restored": true}`); when it did not, send the actor to login. The hard cap
  is a hard boundary — a session past it is refused at validation before any handler runs,
  so a frontend offers *return to self* before `expiresAt` from the `Authenticated()`
  response, or warns and calls it as the cap nears. The route is a POST, so it sits
  outside any group carrying `EnforceReadOnlyMask` (see *Read-only middleware*).

  ```go
  r.Group(func(r chi.Router) {
      r.Use(auth.ValidateSession, auth.ValidateXSRFToken)
      r.Post("/impersonation/end", auth.EndImpersonation())
  })
  ```
- **Validation (`Auth` and the legacy password type).** A user principal's record is looked up like any
  session's — a disabled impersonated user ends the session. A foreign actor's role
  principal has no local user: no record is looked up and `UserFromCtx` carries the
  actor's username with the zero ID, so self-referential checks (cannot delete yourself)
  go inert, correctly. A local actor's role principal is their own session, so their
  record is looked up as usual — a disabled actor's role session ends with their others.
  Preauth and OIDC validate an impersonated session exactly as any other.
- **Identity operations.** The library's own handlers refuse under impersonation:
  `ChangeUserPassword` (the password method's on `Auth`, the legacy password type's)
  and the legacy `ChangeUsername` always (they would alter the impersonated user's
  credentials); the legacy `CreateUser`, `DeactivateUser`, `DeleteUser` and
  `ActivateUser` when the session is masked. Each refusal is an
  `IdentityOperationBlocked` event. On `Auth` the user operations are `AuthAPI` methods
  behind the application's own handlers, which guard them.
- **One name, one user.** A role principal's session carries the actor's own username,
  in the same session table as the application's real users. For a *local* actor that
  name is their user, and the two username-keyed store operations treat everything
  under it as theirs: `DestroyAllUserSessions` expires their own sessions, their role
  sessions, and every impersonation they hold as a local actor under other names, ending
  the records `Revoked`; the session rename on `ChangeUsername` renames their role sessions
  and moves their live records to the new name. For a *foreign* actor the name is
  borrowed, so password auth refuses a role principal when that name is already a
  `SessionUsers` user (the actor logs in as that user, or impersonates it as a user
  principal), and the two operations never touch a session carrying a live foreign
  role-principal record — a user created later under that name cannot reach the
  actor's session either. On `Auth` the same holds by user ID: `DestroyUserSessions`
  ends the user's own sessions under any username, the user-principal impersonations of
  them and every impersonation they hold as a local actor. Preauth and the legacy OIDC
  type have no username-keyed user to collide with; the legacy `FrontChannelLogout` is
  username-keyed all the same, and makes no exception for a foreign role session (see
  *Identity by session type*).
  This is the store-level complement of the authorization rule: under a role principal the
  subject is the role, and application policy must not key row conditions on the session
  username.
- **Listing.** `API().ActiveImpersonations(ctx, q)`, on every session type, lists the
  impersonated sessions that are live right now, newest first — the admin surface's view
  of who is acting as whom. *Active* means: the record has not ended, the hard cap has
  not passed, the session row is not expired, and the session has seen activity within
  the idle session timeout. `q` (`*session.ImpersonationQuery`) narrows by `Actor`
  and/or `Principal`; `nil` lists everything.

  `API().DestroyImpersonatedSession(ctx, sessionID)` is the action on a row: it expires
  that session and ends its record `Revoked` in one transaction, so the next request on it
  is refused. Who may list or revoke is the application's guard.

  ```go
  imps, err := auth.API().ActiveImpersonations(ctx, &session.ImpersonationQuery{Actor: "alice@example.com"})
  err = auth.API().DestroyImpersonatedSession(ctx, imps[0].SessionID)
  ```
- **Read-only middleware.** `EnforceReadOnlyMask` (on every session type, after
  `ValidateSession`) refuses non-safe requests — anything but GET, HEAD, OPTIONS and
  TRACE — from a session whose mask is *read-only*: restricted, and allowing nothing
  beyond `List` and `Read`. The refusal is 403 with a `WriteBlocked` event naming the
  method and path. It is an opt-in backstop that keeps a read-only session away from
  every mutating handler whether or not that handler consults the mask; it does not
  replace honoring the mask in permission checks (`Execute` reaches handlers by POST, and
  a mask including `Execute` is not read-only). Ending a session is never a safe method
  either — `EndImpersonation` is a POST, `Logout` a POST or DELETE — so the
  `EndImpersonation` route (and `Logout`) must be mounted outside the group that carries
  the backstop, in a validated group of their own, or a read-only view-as session could
  never end itself.

  ```go
  // Ending a session is never a safe method: these stay out from under the backstop.
  r.Group(func(r chi.Router) {
      r.Use(auth.ValidateSession, auth.ValidateXSRFToken)
      r.Post("/impersonation/end", auth.EndImpersonation())
      r.Delete("/session", auth.Logout())
  })
  // Everything else a read-only session may reach is under it.
  r.Group(func(r chi.Router) {
      r.Use(auth.ValidateSession, auth.ValidateXSRFToken, auth.EnforceReadOnlyMask)
      // ...
  })
  ```

##### Created and maintained by the CCC team.
