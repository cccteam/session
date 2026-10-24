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
  - Microsoft Entra ID (Azure) OIDC (`session/azure`), admitting one tenant, several, any tenant or Microsoft personal accounts, with role synchronization from the token's roles and provider-initiated logout (see the "Microsoft Entra ID OIDC" section)
  - Google Workspace OIDC (`session/google`), admitting one Workspace, several, any Workspace or any Google account, with role synchronization from Google Groups (see the "Google Workspace OIDC" section)
  - WorkOS SSO: built and tested, but under `internal` in v0.13.0 until its review; it returns to the public API in v0.13.1
- `Invitations, email addresses and sign-up`: an invitation mailed to an address, carrying the roles its acceptance grants, accepted by whoever signs in or signs up at it; a user's email address in two states, unverified and verified, the person proving it by a mailed link; and self-service sign-up with a password when the application opens it. See "Users and their email address", "Invitations" and "Sign-up" under the Auth session.
- `Mail`: one interface the invitation, verification and sign-up flows send through (`session/mail`), with the Google Workspace SMTP relay as the first driver (`session/mail/workspace`). See the "Sending mail" section.
- `Preauth`: trust-the-caller stepping-stone sessions (`session.NewPreauth`).
- `Legacy session types`: the single-method `PasswordAuth` and `OIDCAzure` of earlier releases, kept unchanged in `session/legacy` and deprecated. See the "Legacy session types" section and [docs/upgrading-to-v0.13.md](docs/upgrading-to-v0.13.md).
- `Custom Session Data`: App-defined data attached to each session, resolved atomically at session creation and available to every request. See the "Custom session data" section.
- `Custom User Data`: App-defined durable data attached to the user record — it survives logout, expiry, and regeneration, and dies with the user. See the "Custom user data" section.
- `OIDC User Anchor`: the legacy Azure type's durable user record, keyed by the immutable `(tid, oid)` claim pair; an Auth session's users are `SessionUsers` records for every method. See the "OIDC user anchor" section.
- `Login Refusal Codes`: A refused sign-in returns the browser to the login page with a code, never with text; the page maps the code to a sentence it holds itself. See the "Login refusal codes" section.
- `Attempt limiting`: The password method limits failed attempts per name, known or not, in memory and in the store, and refuses an attempt past the limit with `too_many_attempts` and the wait; an after-sign-in hook is told of every session a sign-in establishes. See the "Attempt limiting and the after-sign-in hook" section.

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
(a session's `CreatedAt`, `UpdatedAt` and `AuthenticatedAt`, a user's `CreatedAt` and
`LastSignInAt`, an auth event's `OccurredAt`, an impersonation record's `StartedAt` and
`EndedAt`, an identity link's `CreatedAt` and `LastUsedAt`, a pending sign-in's
`CreatedAt` and `ConsumedAt`, the OIDC user anchor's `CreatedAt` and `UpdatedAt`) is
written with the database's time, never
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

**The users table carries the user-management columns.** `SessionUsers` has, beside
the username, the password hash and `Disabled`, the password change mark
`PasswordChangeRequired` and the time columns `CreatedAt` and `LastSignInAt` (see
"Users and the forced password change"). The shipped `000002_SessionUsers` migration
creates them; a users table named per group takes the same DDL under its name. The
auth set adds the email address columns `Email`, `NormalizedEmail` and
`EmailVerifiedAt` (`SessionUserEmail`) and the mail links table (`SessionMailLinks`);
see "Users and their email address" for the two shapes the address columns take.

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
| `google` | `google.SignIn(auth, name, rule, &google.Config{...})` → `*google.Method`: `Login`, `Callback` | (the Workspace the `Workspaces` slot selects, `sub`) | `?returnUrl=`, `?login_hint=` | `google.RoleSync(...)` or `google.DisableRoleSync()` |
| `workos` (internal until v0.13.1) | `workos.SignIn(auth, name, rule, &workos.Config{...})` → `*workos.Method`: `Login`, `Callback` | (`connection_id`, `idp_id`) | `?organization=` (required), `?returnUrl=` | never synchronized |

`name` identifies the registration on the `Auth` and must be unique there: one method
may be registered several times under different names, so one `Auth` offers two Entra
tenants as two registrations, each with its own configuration and rules. The password
registration is named `password`. `rule` is the application's own **account rule** for
an identity that is not linked to any user yet, and `nil` is the usual value: the
Entra and Google methods apply a **standard account rule** (`Config.Accounts`) to a
first sign-in (see "Storage and schema").

### Storage and schema

Each auth group owns eight tables: sessions and users (the base migrations,
`schema/*/migrations`), identities, auth events, pending sign-ins, sign-in attempts and
mail links (the auth migrations, `schema/*/auth/migrations`, which also add `UserId`,
`AuthenticatedAt`, `ProviderSessionId` and `ProviderSessionIssuer` to the sessions
table and the email address columns to the users table), and impersonations
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
`WithIdentitiesTableName`, `WithPendingSignInsTableName`,
`WithSignInAttemptsTableName` and `WithMailLinksTableName` on `NewAuth`, and
`NewAuthEventsTable(name)` / `NewImpersonationTable(name)` on the store. A table name
must be a plain identifier (a letter or underscore, then up to 127 letters, digits or
underscores): the store refuses any other, and the constructor reports it under the
option's name, so a name never reaches SQL unchecked. Name the users
table's unique indexes after the table as the shipped DDL does
(`<UsersTable>_NormalizedUsername_idx` and `<UsersTable>_NormalizedEmail_idx` on
PostgreSQL, `<UsersTable>ByNormalizedUsername` and `<UsersTable>ByNormalizedEmail` on
Spanner): the drivers read a username or an address conflict by those names. Build the
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
  none accepts any. An application whose users belong to tenants sets the library's
  **tenant policy** (`signin.TenantPolicy`), with its own rule chained after it when it
  has one; see "The tenant policy".
- The **account rules** decide an identity's first sign-in: an identity that is not
  linked to any user yet. A linked identity signs in by its link and never consults
  them. Each Entra and Google registration declares a **standard rule** in
  `Config.Accounts`, which the library applies inside the sign-in's first transaction:
  - `signin.MembersOfDirectory` (the default): every member of the directory gets an
    account under their **sign-in name**, the user principal name on Entra and the
    verified email on Google. A user the application pre-created is linked instead,
    found by the username first and then by the address: the user under that name,
    matched without regard to case, or else the user who holds the identity's address
    verified, when the method verified the address (Google does, Entra does not), since
    a person is one user whichever way they sign in. The link is made after a password
    confirmation when the user has a password, outright when the user has none and
    signs in through no other connection yet. An address a user holds unverified is a
    reservation, not a match: the person is provisioned as a stranger, and the new
    account holds no address until they verify one, the reserved address staying with
    the account it was entered for. A registration's own rule that provisions a new
    user for an identity whose verified address another user holds verified is refused
    (`identity_rejected`): never a second user for one person.
  - `signin.InvitedUsersOnly`: the same matching, and no provisioning; a person no user
    was created for is refused (`not_invited`), unless the sign-in carries an
    invitation, which is then the account the rule asks for. The application creates the users
    under their sign-in names, with or without a password, before they sign in.
  - `signin.OpenSignUp`: anyone who signs in gets an account under their sign-in name.
    It is for public applications and refused on a registration that serves one
    organization.

  Every standard rule writes nothing for a guest of the directory (an Entra B2B guest,
  refused with `guest_account`: a guest's preferred username is an address the
  directory did not verify), for a token asserting no application role when the method
  synchronizes roles (`no_roles`), or for an identity without a sign-in name
  (`no_email`). The tenant key on the link is the organization the registration names
  for the account (`Identity.Organization`): on Entra the tenant id, or the name
  `azure.NamedTenant` gives it; on Google the Workspace's name, the account's domain
  under any Workspace, `google.AnyAccountConnection` under any Google account.
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
    Tenants: azure.Tenant(cfg.EntraTenantID), ClientID: cfg.EntraClientID, ClientSecret: cfg.EntraClientSecret,
    RedirectURL: cfg.SSORedirectURL, RoleSync: signin.DisableRoleSync(), LoginURL: "/login",
    Accounts: signin.InvitedUsersOnly, // the standard rule: pre-created users only
})
```

`NewAuth` refuses the OIDC-only storage features
(`WithOIDCUsers`, the custom user data login hook).

### The tenant policy

The tenant policy is the library's sign-in rule for an application whose users belong
to tenants: a person signs in when one of their tenants admits the way they signed in.
It is built from two things the application gives it and set like any other policy:

```go
auth.SetSignInPolicy(signin.TenantPolicy(userManager, tenantDeclaration))
```

- **The person's memberships**, read through `userManager`, the access library's user
  manager (`signin.UserRoleManager`, the same store role synchronization reconciles
  through). The person's tenants are the domains where they hold a role; a role held in
  the global partition or in every tenant domain makes the person the application's own
  staff.
- **Each tenant's declaration**, read through `tenantDeclaration`, a
  `signin.DeclarationReader[Tx]` the application writes over its own tenant record,
  typed to the store's transaction like the other hooks and run in the sign-in's:
  `func(ctx, tx, tenant accesstypes.Domain) (*signin.TenantDeclaration, error)`. A
  declaration names the **directories** the tenant admits its people through
  (`signin.Directory`: a method and the connection its identities carry, which is the
  Entra tenant id, the name the registration gives a Google Workspace, or a WorkOS
  connection id) and whether its people come through those **only**
  (`DirectoryOnly`). A tenant that declares nothing (a nil declaration) admits its
  people by password and through no directory.

The rules, in order, once the user is known:

1. A person holding a role in the global partition or in every tenant domain is the
   application's staff and is admitted on the library's own checks; so is a sign-in
   whose method synchronizes roles, since the directory names the person's roles and
   the synchronization, which runs once the session stands, refuses a person with none.
   The application's own directories are admitted by the registration's organization
   slot already.
2. A person who is a member of no tenant is refused (`no_tenant`), unless the policy
   was built with `signin.AdmitWithoutTenant()`, which the self-service shape of an
   application needs: a stranger signs in, then creates their organization and its
   first membership, and until then the session reaches no tenant.
3. A sign-in through a directory (Entra, Google, WorkOS) is admitted when one of the
   person's tenants declares the directory it came through, and refused otherwise
   (`connection_not_in_tenant`).
4. Any other sign-in, a password or a session the application starts for a user it
   authenticated itself, is admitted when one of the person's tenants admits its people
   other than through its directories, and refused when every one of them is directory
   only (`directory_only`): nothing would be reachable.
5. Otherwise the sign-in is allowed. `signin.Policy.Then` chains the application's own
   rule after the tenant policy, for what the tenant policy cannot know; it is asked
   after an `Allow` and never after a `Deny` or a `RequireMFA`:

   ```go
   auth.SetSignInPolicy(signin.TenantPolicy(userManager, tenantDeclaration, signin.AdmitWithoutTenant()).Then(ownRule))
   ```

The policy decides what the session may be and never writes. Which of the person's
tenants the session then reaches is decided again, tenant by tenant, where the
application computes the session's tenant list: `signin.TenantDeclaration.Admits(method,
connection)` is the same decision over one tenant, with no transaction and no reads,
and the session says how it was established through
`sessioninfo.DataFromCtx(ctx).EstablishedBy()`, its first auth event, whose method and
connection are the sign-in's (`sessioninfo.AuthMethod.ThroughDirectory` tells a sign-in
through a directory from the application's own). So a person in a directory-only tenant
and a password-admitting tenant signs in by password and reaches the second; a member
of two tenants with two directories reaches the one whose directory they came through.
A refusal is a `sessioninfo.LoginRefusal` with its code, and `errors.Is` matches
`signin.ErrSignInDenied` and the rule's own cause (`signin.ErrNoTenant`,
`signin.ErrConnectionNotInTenant`, `signin.ErrDirectoryOnly`); a role store or reader
error fails the sign-in (`internal_error`).

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
  own state cookie, `OIDC-<session cookie name>-<name>`, so the name is letters, digits
  and hyphens (`lakeside-entra`): two registrations of one method, logins with different
  providers in one browser, and two `Auth`s on one host with a registration of the same
  name never read each other's state, and a callback completes only the login its own
  registration began.
- **A method registered once the `Auth` is in use**: after it has served a request
  through any of its handlers or middleware, or read its methods to check or hash a
  password through its API (`CreateSessionUser` before `PasswordSignIn(auth,
  HashAlgorithm(...))` would have hashed with the default). Register every method, then
  build the router and serve.
- **A registration without an account rule**: a WorkOS registration with a nil `rule`
  (WorkOS has no standard rule), or a registration naming a standard rule that does not
  exist.
- **A misconfigured method**: Azure or Google without its role sync slot, or with a slot
  missing its manager (or, for Google, its group prefix or lookup); an Azure
  registration without its `Tenants`, a tenant id that is not a GUID, Microsoft's
  consumer tenant listed as a tenant, a tenant listed twice or a name used twice, or an
  `Authority` that is not a base URL; a Google registration without its `Workspaces`, a
  Workspace without a name or a domain, a value that is not a domain name, a name used
  twice or a domain in two Workspaces; role synchronization with other than one tenant
  or one Workspace; open sign-up (`signin.OpenSignUp`) on a registration that serves
  one or several named organizations; members of the directory with any tenant,
  personal accounts, any Workspace or any Google account and no rule of the
  application's own; cookie or session options passed to `PasswordSignIn` instead of
  `NewAuth`.

### Routes

```go
r.Use(auth.StartSession, auth.SetXSRFToken)
r.Get("/api/user/authenticated", auth.Authenticated())
r.Get("/api/user/sso/login", sso.Login())       // ?organization=…&returnUrl=…
r.Get("/api/user/sso/callback", sso.Callback())
r.Get("/api/user/pending", auth.Pending().Status())
r.Get("/api/user/methods", auth.Methods(&session.MethodList{ // what the login page offers
    Methods: []session.AdvertisedMethod{
        {Name: "password", Label: "Password", Path: "/api/user/session"},
        {Name: "workos", Label: "Single sign-on", Path: "/api/user/sso/login"},
    },
    Pending:    session.PendingRoutes{Status: "/api/user/pending", Confirm: "/api/user/pending/confirm", Cancel: "/api/user/pending/cancel"},
    Invitation: session.InvitationRoutes{Open: "/api/user/invitation", Accept: "/api/user/invitation/accept", SignUp: "/api/user/invitation/sign-up"},
    Email:      session.EmailRoutes{Add: "/api/user/email", Verify: "/api/user/email/verify"},
    SignUp:     session.SignUpRoutes{Start: "/api/user/sign-up", Open: "/api/user/sign-up/open", Complete: "/api/user/sign-up/complete"},
}))
r.Group(func(r chi.Router) {
    r.Use(auth.ValidateXSRFToken)
    r.Post("/api/user/session", password.Login())
    r.Post("/api/user/pending/confirm", auth.Pending().ConfirmWithPassword())
    r.Post("/api/user/pending/cancel", auth.Pending().Cancel())
    r.Post("/api/user/mfa", app.CompleteMFA) // checks the app's code, then auth.API().CompletePending
    r.Post("/api/user/logout", auth.Logout())
    r.Post("/api/user/password", password.ChangeUserPassword()) // validates the session itself
    r.Post("/api/user/invitation", auth.Invitation().Open())          // {"token"}: sets the invitation cookie
    r.Post("/api/user/invitation/sign-up", auth.Invitation().SignUp()) // {"password", "username"}: the invited person's account
    r.Post("/api/user/sign-up", auth.SignUp().Start())                 // {"email"}: mails the sign-up link (OpenSignUp)
    r.Post("/api/user/sign-up/open", auth.SignUp().Open())             // {"token"}
    r.Post("/api/user/sign-up/complete", auth.SignUp().Complete())     // {"token", "password", "username"}
    r.Group(func(r chi.Router) {
        r.Use(auth.ValidateSession)
        r.Post("/api/user/invitation/accept", auth.Invitation().Accept()) // the signed-in person accepts
        r.Post("/api/user/email", auth.Email().Add())                     // {"email"}: mails the verification link
        r.Post("/api/user/email/verify", auth.Email().Verify())           // {"token"}
        // …protected routes
    })
})
```

The invitation, email and sign-up handlers are described under "Invitations", "Users
and their email address" and "Sign-up" below; the groups that send mail (`Email()`,
`SignUp()`) panic at wiring on an `Auth` without `WithMail`.

The pending handlers and the API's pending methods read the pending identity
`StartSession` found, so they must run behind it; the POSTs belong behind
`ValidateXSRFToken` like the password login. The session read (`Authenticated`), the
logout and the password change sit outside `ValidateSession`: they validate the session
on their own, and they are what a user who must change their password reaches (see
"Users and the forced password change"). The methods list names the password change
route (`ChangePassword`) whenever it lists the password method.

### What the login page is told

The login page renders from the server, so the browser bundle is the same in every
environment and a method that is not registered has no button. `auth.Methods(list)` is
the public route that tells it: for each method the application lists, its name, the
method behind it, how it starts, its label and its path, in the list's order, the
pending sign-in routes when the list names them, and the password change route when
the password method is listed.

```json
{
  "methods": [
    {"name": "password", "method": "password", "kind": "password", "label": "Password", "path": "/api/user/session"},
    {"name": "workos", "method": "workos", "kind": "redirect", "label": "Single sign-on", "path": "/api/user/sso/login"}
  ],
  "pending": {"status": "/api/user/pending", "confirm": "/api/user/pending/confirm", "cancel": "/api/user/pending/cancel"},
  "changePassword": "/api/user/password",
  "usernameIsEmail": true,
  "invitation": {"open": "/api/user/invitation", "accept": "/api/user/invitation/accept", "signUp": "/api/user/invitation/sign-up",
                 "standing": {"email": "pat@lakeside.edu", "tenant": "", "expiresAt": "2026-10-31T20:00:00Z", "usernameIsEmail": false, "methods": ["workos"]}},
  "email": {"add": "/api/user/email", "verify": "/api/user/email/verify"},
  "signUp": {"start": "/api/user/sign-up", "open": "/api/user/sign-up/open", "complete": "/api/user/sign-up/complete"}
}
```

- `kind` is how the method starts: `password` is a form that posts `{"username",
  "password"}` to `path` and reads the JSON answer of the password login; `redirect`
  sends the browser to `path` (a GET, with `?returnUrl=` naming the page to come back
  to) and the method's callback brings it back. The kinds are
  `signin.KindPassword` and `signin.KindRedirect`.
- `name` is the registration's name on the `Auth`, `method` the method behind it
  (`password`, `azure`, `google`, `workos`), for a page that shows a provider's mark.
- `label` is the application's wording for the method.
- `path`, the pending paths and `changePassword` are the application's: the list is
  written where the routes are wired, so the paths the page is told are the paths the
  router serves. A registered method the list leaves out is not offered.
- `changePassword` is the path of the password method's `ChangeUserPassword` handler,
  which the page posts `{"oldPassword", "newPassword"}` to when a sign-in finds the
  user must change their password (the session read's `passwordChangeRequired`). It is
  present whenever the password method is listed.
- `usernameIsEmail` is present, and true, when the listed password method declares
  the username as the email address (`UsernameIsEmail`): the page then asks for the
  address where it would ask for a username, and a sign-up takes none.
- `invitation`, `email` and `signUp` are the paths of the invitation, email address and
  sign-up handlers, each block present when the list names it (`MethodList.Invitation`,
  `Email`, `SignUp`). The invitation block's `signUp` is named exactly when the
  password method is listed; the sign-up block needs the password method listed and
  registered with `OpenSignUp`. The page opens a link it was sent to with
  `?invitation=`, `?verify=` or `?signUp=` by posting the token to the block's `open`
  (or `verify`) path; see "Invitations", "Users and their email address" and "Sign-up".
- `invitation.standing` is the live invitation the browser carries, present when the
  invitation cookie that `open` set still names an invitation that stands: the address
  it was sent to, its tenant (`""` for the application's global surface), when it stops
  being accepted, whether an account created from it takes the address as its
  username, and the names of the listed external registrations that could admit the
  address (`methods`, empty when none could), as `Invitation().Open()` answered them;
  the page hides the methods not named. A page that arrives without the
  mailed link's token, as it does when an external sign-in was refused and sent the
  browser back with `?code=`, reads the invitation from here and keeps showing it. The
  block is absent when the browser carries no cookie, or its invitation is dead (used,
  revoked or expired).

`Methods` is called after every method is registered and panics on a wiring mistake,
as a registration does: an empty list, a method that is not registered on the `Auth`,
a name listed twice, a method without a label or with a path that is not a canonical
path in the application, a pending block with some of its paths, the password method
without its change route or that route without the method, an invitation, email or
sign-up block with some of its paths, or a sign-up block for a password method that
does not offer sign-up. Route it beside the login routes: behind `StartSession`,
before `ValidateSession`, no XSRF token.

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
| Refused: the name's failed attempts reached the limit | — | `429 {"message", "code": "too_many_attempts", "retryAfter": <seconds>}` with the `Retry-After` header (see "Attempt limiting and the after-sign-in hook") |

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
  sign-in establishes a session (including after a confirmation or MFA). A sign-in
  whose asserted roles the application recognizes none of is refused (`no_roles`)
  before anything is resolved or written, so an invitation it carried stands; a role
  store that fails once the session stands expires the session.
- **Impersonation** works as on the other types. A user principal's session belongs to
  the impersonated user; a role principal's belongs to none. The session records an
  `impersonation` event whose connection is the actor.
- **User management is by ID**: `ChangeSessionUserPassword`, `SetSessionUserPassword`,
  `ResetSessionUserPassword`, `DeactivateSessionUser` and `DeleteSessionUser` destroy
  the user's sessions by `UserId`; `DeleteSessionUser` deletes its identity links with
  it; `UnlinkIdentity` refuses a user's last means of sign-in. See "Users and the forced
  password change".
- **Failed password attempts are limited** per name, known or not, and an attempt past
  the limit is refused with `too_many_attempts` and the wait before anything is read
  or hashed; **the after-sign-in hook** (`SetSignedInHook`) is told of every session a
  sign-in establishes. See "Attempt limiting and the after-sign-in hook".
- **Provider-initiated (front-channel) logout** is keyed by the issuer of the token the
  sign-in verified and the provider's session id, since a provider's session id is
  unique only within its issuer: an Azure sign-in records the ID token's `sid` claim on
  its session row with that issuer (`ProviderSessionId`, `ProviderSessionIssuer`), a
  pending sign-in carries them to the session it completes, and a regenerated session
  keeps them. A registration declares the issuers its tokens may come from
  (`signin.Registration.Issuers`; an Entra registration declares its one tenant's
  issuer, or the issuer of every tenant its `Tenants` slot admits), and a round trip from any other issuer is refused
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

### Users and the forced password change

The `Auth` has no user-management handlers of its own: an application, or a library
over it, manages users through `auth.API()` and guards the callers. The API reads
users as the store holds them (`sessionstorage.SessionUser`: the username, `Disabled`,
the password hash, nil for a password-less user, `PasswordChangeRequired`, `CreatedAt`
and `LastSignInAt`, nil before the first sign-in) and writes them by ID:

| Call | What it does |
| --- | --- |
| `Users(ctx)` | Every user, by username. |
| `User(ctx, id)`, `UserByUsername(ctx, username)` | One user; the username is matched without regard to case. |
| `CreateSessionUser(ctx, &CreateUserRequest{Username, Password, Disabled, PasswordChangeRequired, Email})` | A user, password-less when `Password` is nil. `PasswordChangeRequired` marks a password an operator set (needs a `Password`). |
| `ChangeSessionUserUsername(ctx, id, username)` | Renames the user and its live sessions. |
| `ChangeSessionUserPassword(ctx, w, id, &ChangeSessionUserPasswordRequest{OldPassword, NewPassword})` | The user's own change: the old password must match and the new one differ. Clears the mark, destroys the sessions and continues in a new one. `PasswordMethod.ChangeUserPassword()` is this over HTTP. |
| `SetSessionUserPassword(ctx, id, password)` | A password the user chose through a flow of the application's own that proved who they are (a reset link, an enrollment). Clears the mark, destroys the sessions. |
| `ResetSessionUserPassword(ctx, id, temporary)` | A temporary password an operator chose. Sets the mark, destroys the sessions. |
| `DeactivateSessionUser`, `ActivateSessionUser`, `DeleteSessionUser`, `DestroyUserSessions` | As named; the first and the third destroy the sessions first. |
| `Identities(ctx, id)`, `UnlinkIdentity(ctx, identityID)` | The user's identity links; unlinking a password-less user's last link is refused (Conflict). |
| `UserByEmail(ctx, email)`, `SetSessionUserEmail(ctx, id, email)` | The user holding an address, verified or not; an operator's entry of an address, unverified, or its removal (nil). See "Users and their email address". |
| `Invite(ctx, &InvitationRequest{Email, Tenant, RoleNames, InvitedBy})`, `Invitations(ctx)`, `RevokeInvitation(ctx, id)` | An invitation mailed to an address; the invitations that stand; one withdrawn. See "Invitations". |

**The forced password change.** A password an operator set, at creation
(`PasswordChangeRequired`) or by a reset, is temporary: the user changes it before
anything else is served. While the mark is set, `ValidateSession` (and
`AuthAPI.ValidateSession`) refuses every request with 403 and `{"message", "code":
"password_change_required"}`; the session read answers, with `"passwordChangeRequired":
true`, and the logout and the password change go through, since they validate the
session on their own, which is why the three sit outside `ValidateSession` in the
wiring above. A login page that reads the mark from the session read posts the change
to the methods list's `changePassword` path before it opens the application. The change
clears the mark, regenerates the session and records a `password` event; an
impersonated session is the actor's and is not held to the user's mark. The seed user
of a new application and every user an operator creates with a password carry the
mark; the password a user chose through `ChangeSessionUserPassword` or
`SetSessionUserPassword` clears it. A password-less user has nothing to change, so the
mark without a password is refused.

### Users and their email address

A user may hold one email address, in two states. **Verified before trusted**: an
address is trusted for nothing until the person has proven they read it by following
a link sent to it, and the user record carries the time that happened
(`SessionUser.EmailVerifiedAt`, `UserInfo.EmailVerified()`). Code that sends a link
may use an unverified address; code that relies on one (linking a social identity, a
recovery) requires the time. No address is required of any user: an account without a
verified address has no mail-based recovery, and multi-factor authentication can serve
instead. The address is unique among every address held, verified or not, matched
without regard to case (`NormalizedEmail`), so an address is held by one account at a
time.

How an address gets onto a user:

- **The person adds and verifies their own**, signed in: `Email().Add()` takes
  `{"email"}` and mails the address a link; nothing is written until the person
  follows it and the page posts the token to `Email().Verify()`, which writes the
  address verified, replacing whatever the user held. The link counts only for the
  account that asked for it, so following a link never attaches an address to an
  account the follower does not control. A directory's claim (Entra's user principal
  name, Google's address) is offered as a prefill of that step through the session
  read's `emailHint`, and never stored by it. `Add` answers `{}` whatever the address's
  state, so the screen reveals nothing: an address another account holds is told so
  by mail to that address, and an address the user already holds verified gets no
  mail. A mailbox is sent at most three links within fifteen minutes; the fourth is
  refused with `too_many_attempts` and the wait, as a locked name is.
- **An operator enters one**, unverified: `CreateUserRequest.Email` or
  `SetSessionUserEmail`. The entry reserves the address within the auth: a later
  sign-up with it is pointed at this account by mail, and the person verifies it
  through the same add step. An entry over a verified address leaves it unverified.
- **Google writes its own**: a Google sign-in writes the address Google verified
  onto the user, verified at the time of the sign-in, when the user holds no verified
  address yet and no other user holds it (any method that asserts
  `Identity.EmailVerified` does the same; Entra does not, so an Entra user's address
  stays a prefill until the person verifies it). The other way round, a first Google
  sign-in by a person whose address a user already holds verified is that user's: the
  standard account rules match the user by the address once no user is under the
  sign-in name (see "Storage and schema" above).
- **An invitation or a sign-up proves it**: the account an invited person creates, or
  an existing account that accepts an invitation while holding no verified address,
  takes the invitation's address verified; a sign-up's account is created with its
  address verified.

**Two shapes.** An application declares on the password method whether the username
is the email address (`session.UsernameIsEmail()`), and the users table takes the
matching shape:

- **Apart** (the default): the username is chosen, the address is added and verified
  separately, and sign-in is by username. The auth set's `SessionUserEmail` migration
  creates the columns as plain columns.
- **One value** (`UsernameIsEmail()`): the address is the username, derived from it by
  the database so the two cannot diverge. The login page asks for the address, a
  sign-up's username is the address, renaming a user is refused
  (`ChangeSessionUserUsername`: Conflict) as is an operator's entry of an address, and
  a person who verifies a new address is renamed to it with their live sessions, as
  the rename does; an application that keys anything by the username, role
  memberships above all, is told of that rename through `auth.SetUserRenamed(func(ctx,
  userID, from, to) error)` and moves what it holds. The store is told the shape when
  the method registers. The users
  table is created with the address columns generated from the username, in place of
  the migration's first two statements:

  ```sql
  -- Spanner
  ALTER TABLE SessionUsers ADD COLUMN Email STRING(MAX) AS (Username) STORED;
  ALTER TABLE SessionUsers ADD COLUMN NormalizedEmail STRING(MAX) AS (NORMALIZE_AND_CASEFOLD(Username)) STORED;
  -- PostgreSQL
  ALTER TABLE "SessionUsers" ADD COLUMN "Email" character varying GENERATED ALWAYS AS ("Username") STORED;
  ALTER TABLE "SessionUsers" ADD COLUMN "NormalizedEmail" character varying GENERATED ALWAYS AS (casefold(normalize("Username"))) STORED;
  ```

  `EmailVerifiedAt` and the unique index on `NormalizedEmail` are as the migration has
  them. Sign-in by address when the two are apart is not offered.

The session read (`Authenticated`) reports `email`, `emailVerified` and, for a user
without an address, `emailHint`.

### Invitations

An invitation is a mailed link that brings a person into the application, or into
one of its tenants, with the roles it carries. It reaches anyone by address, and the
actor's request is the same whether an account already holds the address or not: only
the invitee's path differs, and the actor does not learn which. Whoever follows the
link and signs in, by any method, or signs up with a password, accepts it: the person
proved they read the mailbox, and the account they sign in with is theirs.

- **Sending**: `auth.API().Invite(ctx, &session.InvitationRequest{Email, Tenant,
  RoleNames, InvitedBy})` stores the invitation and mails the link; it stands for
  `MailSettings.InvitationTimeout` (seven days). `Invitations(ctx)` lists those that
  stand; `RevokeInvitation(ctx, id)` withdraws one. The tenant and the roles are the
  application's, opaque to the library.
- **Opening**: the login page, sent to with `?invitation=<token>`, posts the token to
  `Invitation().Open()`, which answers `{"email", "tenant", "expiresAt", "signUp",
  "usernameIsEmail", "methods"}` and sets an encrypted cookie holding the token, so the
  sign-in that follows carries the invitation, an external round trip included. The
  page then offers the sign-in methods, and, when `signUp` is true (the password method
  is registered), an account with a password. `methods` names the listed external
  registrations that could admit the invitation's address, by the names the methods
  listing advertises them under (`[]` when none could; the password method is never
  among them), so the page hides the buttons that would refuse the invitee. While the cookie names an invitation that
  stands, the methods listing (`auth.Methods`) reports it as `invitation.standing`, so
  the page shows the invitation again when it comes back without the token, as after a
  refused external sign-in; see "What the login page is told".
- **Accepting**: a sign-in that carries an invitation accepts it once the user is
  known, before the sign-in policy decides, so the policy sees the membership: the
  invitation is consumed, the user takes its address when they hold no verified one,
  and the application's hook grants what it names. Only a sign-in the resolution
  admitted consumes it: one the account rules refuse or hold for a confirmation, one
  the directory's roles refuse (`no_roles`), or a disabled user's leaves the
  invitation standing with nothing granted, and the person may sign in another way;
  once accepted, a sign-in the policy then denies leaves what the acceptance granted
  in place. The hook is set with
  `auth.SetInvitationAccepted(func(ctx, userID, username, inv) error)` and runs once
  the transaction that consumed the invitation has committed (for an external
  identity, the resolution's own, so a user the invitation provisioned is committed
  when the hook sees them), outside any transaction: an application's memberships
  live in a store of their own, written through its own client, which no transaction
  of the session store can carry, and which the Spanner emulator, allowing one
  read-write transaction at a time, would deadlock inside one. Under the
  invited-users-only account rule the invitation is the account the rule asks for: a
  stranger who carries one is provisioned under their sign-in name. A person already
  signed in accepts with `Invitation().Accept()` (behind `ValidateSession`); an
  invited person creates an account with a password through `Invitation().SignUp()`
  (`{"password", "username"}`), which creates the user with the invitation's address
  verified and signs them in, the invitation accepted on the way. `NewSessionRequest.Invitation`
  carries it to the policy, with `Accepted` saying whether this sign-in accepted it.
- **A dead invitation** (used, revoked or expired) is skipped by a sign-in the person
  was admitted to anyway, which goes on without a grant, and refuses one the invitation
  alone admitted (`invitation_expired`), provisioning nothing. A hook that fails ends
  the sign-in with its error and writes no session; the invitation stays consumed and a
  user it provisioned stays, so the person's next attempt at the link finds it dead and
  an administrator invites again.

An invitation is refused before anything is stored or mailed when no sign-in method the
login page offers could admit the address, so the sender learns it now rather than the
invitee at the sign-in: `Invite` answers a bad request reading `No sign-in method of
this application accepts an address at <domain>.` The password method, when it is
listed to `Methods`, admits any address, since the invited person creates an account
with a password; a Google registration admits an address at a domain of its named
Workspaces, any domain but `gmail.com` and `googlemail.com` under `AnyWorkspace`, and
any under `AnyGoogleAccount`; a Microsoft Entra registration refuses only a personal
account's address (`outlook.com`, `hotmail.com`, `live.com`, `msn.com`) unless it admits
`PersonalAccounts`, since a tenant is not a domain; WorkOS and a method of your own that
sets no `signin.Method.AdmitsAddress` cannot tell, which admits. Google puts the
Workspace's primary domain in the `hd` claim, so an invitation to an address at a
secondary domain of a Workspace whose primary domain alone is named is refused here
although Google would admit the sign-in: name the secondary domain on the Workspace too.

### Sign-up

When the password method is registered with `session.OpenSignUp()`, anyone may create
an account: the person gives their address to `SignUp().Start()` (`{"email"}`), which
mails a link standing `MailSettings.LinkTimeout` (a day); the login page, sent to with
`?signUp=<token>`, posts the token to `SignUp().Open()` for `{"email",
"usernameIsEmail"}` and then, with the password the person chose (at least eight
characters) and the username when the two are apart, to `SignUp().Complete()`, which
creates the account with the address verified and signs the person in, answering as
the password login does. `Start` answers `{}` whatever the address's state: an address
an account already holds is pointed at that account by mail, and the screen says
nothing. `OpenSignUp` needs mail (`WithMail`), and the sign-up routes are offered only
with it; without `OpenSignUp` the handlers answer 404 and `Methods` refuses the block.

### Attempt limiting and the after-sign-in hook

The password method limits failed attempts itself. Five wrong passwords on a name
within fifteen minutes lock the name for fifteen minutes, whether a user exists under
the name or not; an attempt during the lock is refused with `too_many_attempts` and the
wait, before the user is looked up or the password hashed; the right password resets
the count. The thresholds are an option of `PasswordSignIn`:

```go
password := session.PasswordSignIn(auth, session.AttemptLimit(5, 15*time.Minute, 15*time.Minute))
```

`AttemptLimit(failures, window, lock)` reads: `failures` failed attempts on a name within
`window` lock the name for `lock`. The default is the line above. The limit is at least
one failure within a positive window and lock; any other panics at registration, as a
misregistered method does.

**What counts, and against what.** Every password check the library makes is held to
the limit: the login (`PasswordMethod.Login()`), the API's `ValidateCredentials`, and
a pending identity's password confirmation (`Pending().ConfirmWithPassword()`,
`ConfirmPendingWithPassword`), under the name the attempt names, as the users table
normalizes usernames (`Pat@Lakeside.edu` and `pat@lakeside.edu` are one name). A wrong
password, an unknown name and a password-less user all count, and all answer the same
`401 {"message": "Invalid Credentials"}` in the same time: a name with no user or no
password is compared against a dummy hash the method's hasher made, so timing no
longer tells an existing name from an unknown one. A matching password resets the
name, as do an MFA completion (`CompletePending`) and a password change of any kind
(`ChangeSessionUserPassword`, `SetSessionUserPassword`, `ResetSessionUserPassword`).
Nothing locks a user an operator must unlock: the lock passes on its own, and a
password change lifts it.

**The three layers.** The name's count is durable: a row of the sign-in attempts table
(`SessionSignInAttempts`, keyed by the name, never a column on the user row), written
on failures and locks only and read through a short-lived per-instance cache, so every
instance refuses a locked name. Over it, each instance holds three kinds of key in
memory, in a bounded table: the name, the client's address and the login's XSRF cookie
token, the cookie the XSRF guard reads (a POST without it never reaches the handler).
During a name's lock every attempt on it is refused the moment it arrives, from memory,
with the same answer and the remaining wait: nothing is read, written or hashed. An
early retry during a wait counts against the client's address and cookie, never against
the name, so a script that ignores the wait extends its own lock while the name's stays
as it was, and a person who waits is not locked out by someone hammering their name.
The client's keys are each allowed ten times the name limit's failures, across names,
within the window; past that the client is locked for the lock period and every retry
extends it. The address is the one a proxy reports (`True-Client-IP`, `X-Real-IP`, the
first `X-Forwarded-For` entry) or the connection's; it is a throttle, not a security
boundary, since the headers are the client's to forge, and a client cycling cookies is
held by the name and the address, one cycling addresses by the edge's own throttle. The
cookie carries no state and nothing new is written to it. In front of it all sits the
edge: a per-address throttle on the sign-in route, outside the library.

**The answer.** A locked name, and a held client, get `429 {"message", "code":
"too_many_attempts", "retryAfter": <seconds>}` with the standard `Retry-After` header,
and nothing about the name; `ValidateCredentials` and `ConfirmPendingWithPassword`
return a `*sessioninfo.LoginRefusal` carrying `RefusedTooManyAttempts`, whose wait
`sessioninfo.RetryAfterOf(err)` reads. A login page that reads `code` from a refusal's
body shows its sentence for `too_many_attempts` (and may show the wait); the external
methods are not limited, since the provider checks their passwords.

**The after-sign-in hook.** One function per `Auth`, set once like the sign-in policy,
is called once for every session a sign-in establishes, after the transaction that
inserted it has committed: a password or external sign-in, a password confirmation, an
MFA completion, a session the application started (`StartAuthenticatedSession`). It
receives the session, its user and the auth events the session recorded, and never
hears of a refused sign-in or one held for confirmation or MFA. An error from the hook
is logged; the session stands. A regenerated session (a password change) and an
impersonation are not sign-ins and are not reported.

```go
auth.SetSignedInHook(func(ctx context.Context, s *session.SignedIn) error {
    return audit.SignedIn(ctx, s.UserID, s.Username, s.SessionID, s.Reason, s.Events)
})
```

A nil hook, a second hook, or a hook set once the `Auth` is in use panics, as
`SetSignInPolicy` does: set it after `NewAuth` and before serving.

## Sending mail

The library sends mail for the flows that need a link in someone's mailbox: the
invitation a tenant's administrator sends to an address, the link that verifies an
address a person adds or changes, and the link a password sign-up starts from. It writes
to one interface, `mail.Sender` (`session/mail`), and knows nothing of the mail system
behind it; an application configures a driver and hands it to the `Auth`. A message is
plain text with one link in it (`mail.Message`: the recipient, the subject and the body),
and every message is from the one address the driver is configured to send as. A message
reads as instructions: what the person did, the link to open and how long it is good for
(`LinkTimeout` or `InvitationTimeout`, said as a duration such as "6 hours", since the
person knows when the message reached them), then, under headings of their own, what to
do if it was not them and a word to keep the link to themselves. Tests use
`mail.Recorder`, a sender that keeps what it was asked to send.

The first driver is the Google Workspace SMTP relay, `session/mail/workspace`. Google
Cloud has no outbound mail service of its own and blocks port 25 from every compute
product, so a mail server of our own is not an option there; the relay is Google's own
route. The driver submits each message to `smtp-relay.gmail.com` on port 587 over TLS,
which Cloud Run allows, logged in as one mailbox of the organization's Workspace domain
with an app password, and Google carries delivery, reputation and signing from there.
The mailbox is the From address of every message, a no-reply address as a rule; where
the no-reply address is an alias of a real account rather than a mailbox of its own, the
account logs in and `From` names the alias, since Google issues no login to an alias
while the relay accepts any From address in the organization's domains once the login is
a real account.

```go
sender, err := workspace.New(&workspace.Settings{
	Mailbox:     "ops@example.com",        // the Workspace account the relay is logged in to
	From:        "no-reply@example.com",   // the address every message is from; empty is the mailbox
	AppPassword: settings.MailAppPassword, // the account's app password, from the secret store
	Name:        "Harbor",                 // the display name beside the address
})
```

What the Workspace side needs, once per organization:

1. **The mailbox**, a Workspace user such as `no-reply@example.com`, or a real account
   with `no-reply@example.com` as one of its alias addresses, with two-step verification
   turned on and an app password generated for it (the account's security settings,
   under two-step verification). Google issues app passwords only to accounts
   with two-step verification; the password stands in for the account's at the relay's
   login and carries no second step, which is what a service needs. Two-step verification
   itself protects interactive sign-ins to the mailbox and the driver never meets it.
2. **The relay service**, in the admin console under Gmail routing: the SMTP relay
   service accepting mail from addresses in the organization's domains, with SMTP
   authentication required and TLS required.
3. **The secret**: the app password goes into the deployment's secret store as a pinned
   version (bedrock refuses a release where the pin is missing). Rotating it is
   generating a new app password and pinning the new version; nothing in the application
   changes.

The `Auth` is given the sender with `WithMail`, with the application's name and the
absolute URL of its login page, where every mailed link leads
(`?invitation=<token>`, `?verify=<token>`, `?signUp=<token>`):

```go
auth, err := session.NewAuth[session.NoCustomData, session.NoCustomData](store, cookieKey,
	session.WithMail(sender, session.MailSettings{Application: "Harbor", LoginURL: "https://harbor.example.com/login"}))
```

In development `mail.Log{}` stands in for a driver: it writes each message to the log,
link included, and sends nothing, so the link is followed from the log. It is never
configured for a deployed environment, where the links are secrets.

The relay allows a sending address ten thousand messages a day, counted apart from the
mailbox's own sending. A refused login comes back in the relay's words after the driver's
sentence saying what the login takes; a refused recipient and a refused message likewise.
A send is given thirty seconds (`Settings.Timeout`), dialing included. An organization
that forbids app passwords has the relay's IP allowlist (a fixed outbound address per
environment) or the Gmail API with domain-wide delegation as its alternatives; neither is
built.

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
    Tenants: azure.Tenant(tenantID), ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
    RoleSync: signin.RoleSync(userRoleManager), // or signin.DisableRoleSync(); one tenant is the shape it runs with
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

## Microsoft Entra ID OIDC

Microsoft Entra ID sign-in is a method of the `Auth` session, registered with
`azure.SignIn(auth, name, rule, &azure.Config{...})` from the `session/azure` package
(see "Registering sign-in methods" above). The identity is linked to its user by the
tenant and the object id, the `tid` and `oid` claims, under every shape below. Its
sign-in name is `preferred_username`, the user principal name, so the standard account
rules (`Config.Accounts`) provision and match users under it. A guest of the tenant (a
B2B guest, whose `idp` claim names another provider than the issuer or whose name
carries `#EXT#`) is marked on the identity (`Identity.Guest`) and refused by the
standard rules (`guest_account`); a rule of the application's own decides for itself.

### Which accounts may sign in

`Config.Tenants` is required and says which Microsoft Entra tenants' accounts a
registration admits. The verified ID token's `tid` claim selects the entry at the
callback, before the account rules run, so an account the slot does not admit never
reaches a row (`unlisted_tenant`, or `personal_account` for a Microsoft personal
account under a work or school shape). The entry also decides the organization the
standard rules store as the tenant key of the links they make
(`Identity.Organization`); the link's connection is the tenant id under every shape.

- **One tenant**, `azure.Tenant("<tenant id>")`: the application that belongs to one
  organization, as a single-tenant app registration serves it. The registration reads
  its provider configuration at the tenant's own endpoint, whose document names the
  tenant's issuer, so every token is held to it. `azure.NamedTenant(id, "lakeside")`
  gives the tenant the application's own name, stored as the tenant key in place of
  the id. This is the only shape role synchronization runs with, since a token's
  application roles are asserted by the tenant that issued it.
- **Listed tenants**, `azure.Tenants(azure.Tenant(...), azure.NamedTenant(...))`: the
  `tid` claim selects the entry, and a tenant outside the list is refused. A tenant id
  is listed once and a name is used once.
- **Any tenant**, `azure.AnyTenant()`: the work or school account of any Microsoft
  Entra tenant, and no personal account. The tenant key is the tenant id; name the
  tenants you know beside it (`azure.Tenants(azure.NamedTenant(...), azure.AnyTenant())`)
  and theirs is the name.
- **Personal accounts**, `azure.PersonalAccounts()`: Microsoft personal accounts
  (outlook.com, hotmail.com, Xbox), which Microsoft issues from one consumer tenant
  (`azure.ConsumerTenantID`), alone or beside any tenant or listed tenants.

Several tenants, any tenant and personal accounts are served through Microsoft's shared
endpoints (`organizations`, `consumers` or `common`, as the shape calls for), whose
discovery documents name their issuer with a placeholder; the app registration must
then admit accounts in any organizational directory, and personal accounts when the
slot does. A shared document cannot hold a token to an issuer, so this library checks
the token's issuer against the token's tenant itself, `<Authority>/<tid>/v2.0`, and
the tenant against the slot, in the verifier and again in the method, before any user
is resolved; the signature, audience and expiry are checked as always.

A first sign-in through an open entry (any tenant, personal accounts) cannot take
members of the directory, which would sign up the world: the registration takes
`signin.InvitedUsersOnly`, `signin.OpenSignUp` or a rule of the application's own.
Open sign-up, in turn, is refused on a registration that lists its tenants only.

`Config.Authority` is the Microsoft identity platform the tenants live on,
`https://login.microsoftonline.com` when empty; Azure Government tenants live at
`https://login.microsoftonline.us`. There is no issuer setting: a tenant's issuer is
`<Authority>/<tenant id>/v2.0`, and `azure.TenantOfIssuer` reads a v0.12 issuer into
the authority and the tenant it names.

### Provider-initiated logout

Entra calls the application's front-channel logout URL (`FrontChannelLogout`) with
`sid` and `iss` when the person signs out of Microsoft. The handler ends every session
whose sign-in carried that `sid` under that issuer, impersonations started from them
included, and refuses an issuer of no tenant the registration admits. A registration
serving one tenant supplies its issuer when the request names none; one serving several
needs the `iss` Entra sends. See "Every session" for the design.

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

There is no issuer or authority setting — Google operates a single issuer for all orgs;
tenancy is the `hd` claim, not the issuer. The identity is linked to its user by its
connection and the `sub` claim: `sub` is globally unique among all Google identities
and never reused, and the connection is what the registration's `Workspaces` slot
selects for the account (below). The sign-in events carry it too, so a policy tells
Workspaces apart by connection and, within one, domains apart by the identity's
`HostedDomain`.

The identity's sign-in name is the verified `email` claim (`email_verified` is
enforced), so the standard account rules (`Config.Accounts`) provision and match users
under it. Google has no `end_session_endpoint` and issues no `sid` claim, so there is no
Google-initiated logout: `Logout` destroys the local session only. The `RoleSync` slot
is `google.RoleSync(manager, groupPrefix, lookup)` or `google.DisableRoleSync()` (see
"The group naming convention").

### Which accounts may sign in

`Config.Workspaces` is required and says which Google accounts a registration admits.
The verified ID token's `hd` claim, the domain of the account's Workspace, selects the
entry at the callback, before the account rules run, so an account the slot does not
admit never reaches a row (`not_workspace_member`). The entry also decides the
connection written on the identity link:

- **One Workspace**, `google.Workspace("lakeside", "lakeside.edu", "lakeside.org")`:
  the application that belongs to one organization. The name is the application's own
  name for the Workspace, written as the connection of every link made through it,
  since Google puts no stable organization id in the token and one Workspace answers
  for every domain it owns; the domains are checked against the `hd` claim. This is
  the only shape role synchronization runs with, since the group lookup reads one
  Workspace's directory.
- **Listed Workspaces**, `google.Workspaces(google.Workspace(...), google.Workspace(...))`:
  the `hd` claim selects the Workspace whose domains contain it, and that Workspace's
  name is the connection. A domain belongs to one Workspace, and a name is used once.
- **Any Workspace**, `google.AnyWorkspace()`: any `hd` claim is admitted and none is
  refused. The connection is the account's domain, lowercased, since the registration
  names no Workspace; name the Workspaces you know beside it
  (`google.Workspaces(google.Workspace(...), google.AnyWorkspace())`) and their members
  share one connection across their domains.
- **Any Google account**, `google.AnyGoogleAccount()`: a token with or without an `hd`
  claim. An account outside the named Workspaces carries the connection
  `google.AnyAccountConnection`. The OAuth client's consent screen must be *External*
  and published for accounts outside your own Workspace to reach the callback;
  *Internal* restricts it to your Workspace.

A first sign-in through an open entry (any Workspace, any Google account) cannot take
members of the directory, which would sign up the world: the registration takes
`signin.InvitedUsersOnly`, `signin.OpenSignUp` or a rule of the application's own.
Open sign-up, in turn, is refused on a registration that names its Workspaces only.

**The connection is a key.** Renaming a Workspace, or moving from any Workspace (where
the domain is the connection) to a named one, makes every sign-in from it arrive as an
unknown identity until the links are re-keyed:

```sql
UPDATE SessionIdentities SET "Connection" = 'new' WHERE "Method" = 'google' AND "Connection" = 'old'
```

Two layers restrict an application to your own organization: the OAuth client's
*Internal* consent screen (Google refuses users outside the org with an `org_internal`
error before they reach the callback) and the one-Workspace slot, the trusted backstop
even with the consent screen in place.

### Skipping Google's account chooser

With one Workspace on one domain the authorization request hints that domain, and
Google skips its account chooser when exactly one signed-in account is in it; with
several domains, several Workspaces or any Workspace it hints any Workspace account,
and the chooser appears whenever more than one Workspace account is signed in; with any
Google account it hints nothing. `Login` accepts `?login_hint=<email>` beside
`returnUrl` and passes it to Google as `login_hint`: Google picks that account when it
is signed in and pre-fills the sign-in form otherwise, so an identifier-first login
page (the person types their email, the page picks the registration) skips the chooser
whatever the registration's shape. It is a hint and is never read back; the
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
lowercase, so the candidate names are lowercase; the store resolves each without regard
to case (`ResolveRole`) and the sync writes the role in the store's spelling, so the
application's roles keep whatever spelling they have.

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

## The simulated sign-in (`skipAuth`)

Built with the `skipAuth` build tag, the Azure and Google methods contact no provider:
the login route sends the browser straight to the callback, and the callback signs in
the person the environment names, with the roles it names. `APP_USERNAME` is the
person (the Azure `preferred_username`, the Google verified `email`) and `APP_ROLES`
the roles, comma-separated (the Azure `roles` claim, the Google groups the simulated
lookup answers). A registration reads its own pair first, `APP_<NAME>_USERNAME` and
`APP_<NAME>_ROLES`, with the registration's name upper-cased and every character
outside letters and digits written as an underscore (`lakeside-entra` reads
`APP_LAKESIDE_ENTRA_USERNAME`), and the shared pair when its own is unset. An
application with one registration sets the shared pair alone; one with several in one
process (a console's `google` beside a portal's `directory`) gives each its own person.
The tag is for development: a `skipAuth` binary admits whoever the environment names.

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
| `verify_id_token_failed` | `RefusedIDTokenVerification` | The ID token failed signature, issuer, audience, or expiry verification; under an Entra shape served through a shared endpoint, a token whose issuer is not its tenant's or that names no tenant. |
| `parse_claims_failed` | `RefusedClaimsParse` | The verified ID token's claims would not decode. |
| `not_workspace_member` | `RefusedNotWorkspaceMember` | Google: the user is outside the Workspace domain logins are restricted to. |
| `unlisted_tenant` | `RefusedUnlistedTenant` | Entra: the token's tenant is outside the registration's `Tenants` slot. |
| `personal_account` | `RefusedPersonalAccount` | Entra: a Microsoft personal account under a registration that admits work or school accounts only. |
| `email_not_verified` | `RefusedEmailNotVerified` | Google: the user's email address is not verified. |
| `organization_mismatch` | `RefusedOrganizationMismatch` | WorkOS: the profile belongs to another organization than the login requested. |
| `no_roles` | `RefusedNoRoles` | The directory asserted no role the application recognizes: refused before anything is resolved or written, or by role synchronization once the session stood, for a method that cannot tell beforehand. |
| `no_email_claim` | `RefusedNoEmailClaim` | Google: the ID token carries no `email` claim. |
| `identity_rejected` | `RefusedIdentityRejected` | Auth: the account rule rejected the identity (its own code wins when it sets one), linked a user that has a password without confirmation, a password-less user who signs in through another connection was matched or linked without trust, provisioned a new user for an identity whose verified address another user holds verified, or the identity resolved to another user than it waited on. |
| `not_invited` | `RefusedNotInvited` | Auth: under the invited-users-only account rule, no user was created for the identity's sign-in name. |
| `invitation_expired` | `RefusedInvitationExpired` | Auth: under the invited-users-only account rule, the invitation the sign-in carried, which alone admitted the person, had expired or been used by the time the sign-in accepted it; nothing is provisioned. |
| `guest_account` | `RefusedGuestAccount` | Auth: the identity is a guest of its directory (an Entra B2B guest), which the standard account rules refuse. |
| `policy_denied` | `RefusedByPolicy` | Auth: the sign-in policy denied the sign-in (its own code wins when it sets one). |
| `user_disabled` | `RefusedUserDisabled` | Auth: the sign-in resolved to a disabled user. |
| `pending_expired` | `RefusedPendingExpired` | Auth: a confirmation or MFA step arrived after its pending identity expired or was used. |
| `no_email` | `RefusedNoEmail` | The external identity carries no email address where one is required: an application's rule asks for one, or a standard account rule found no sign-in name to use as the username. |
| `password_change_required` | `RefusedPasswordChangeRequired` | Auth: the signed-in user must change a password an operator set; answered with 403 by `ValidateSession` on every request but the password change, the session read and the logout, until the change (see "Users and the forced password change"). |
| `no_tenant` | `RefusedNoTenant` | Auth, the tenant policy: the person is a member of no tenant, and the policy was not built with `signin.AdmitWithoutTenant()`. |
| `connection_not_in_tenant` | `RefusedConnectionNotInTenant` | Auth, the tenant policy: the sign-in came through a directory (its method and connection) that no tenant of the person declares. |
| `directory_only` | `RefusedDirectoryOnly` | Auth, the tenant policy: a sign-in that is not through a directory (a password, a session the application started itself) by a person whose every tenant admits its people through their directories only. |
| `too_many_attempts` | `RefusedTooManyAttempts` | Auth: a password attempt on a name whose failed attempts reached the limit, or from a client held for its own; answered with 429, the wait in seconds as `retryAfter` and the `Retry-After` header, until the lock passes (see "Attempt limiting and the after-sign-in hook"). |

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
