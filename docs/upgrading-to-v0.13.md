# Upgrading to v0.13

v0.13.0 makes `Auth` the session type for every sign-in method. The single-method types
that predate it, `PasswordAuth` and `OIDCAzure`, move to the `legacy` package unchanged
and deprecated. The Google single-method type of v0.12 (`OIDCGoogle`) is removed: Google
Workspace sign-in is a method of `Auth`. Each redirect-based method is its own package,
`session/azure` and `session/google`, over the `session/signin` contract and the shared
`session/oidc` machinery; the WorkOS method is built but waits under `internal` until its
review lands in v0.13.1.

An application takes this in two steps, and only the first has to happen at the
upgrade:

1. **Keep the legacy type.** An import edit and, on Spanner, the time-column
   migrations of the sets the group applies (see "Time columns" below). No behaviour
   change.
2. **Move to `Auth`.** New sign-in and user-management code and one of the shipped
   schema upgrade sets, when the application is ready.

## 1. Keep the legacy type

Replace the root package's names with the `legacy` package's. The types, their
handlers, their APIs and their storage are the ones v0.12 shipped, and so is their
schema but for the time columns, which on Spanner must allow commit timestamps before
the v0.13 driver writes to them (see "Time columns"). Each legacy type logs one warning
when it is constructed, saying it is deprecated.

| v0.12 (`session`) | v0.13 (`legacy`) |
| --- | --- |
| `NewPasswordAuth`, `PasswordAuth` | `legacy.NewPasswordAuth`, `legacy.PasswordAuth` |
| `PasswordAuthHandlers`, `PasswordAuthAPI` | `legacy.PasswordAuthHandlers`, `legacy.PasswordAuthAPI` |
| `RouterSessionUserID` | `legacy.RouterSessionUserID` |
| `NewOIDCAzure`, `OIDCAzure` | `legacy.NewOIDCAzure`, `legacy.OIDCAzure` |
| `OIDCAzureHandlers`, `OIDCAzureAPI` | `legacy.OIDCAzureHandlers`, `legacy.OIDCAzureAPI` |
| `OIDCAzureOption`, `OIDCOption`, `WithLoginURL` | `legacy.OIDCAzureOption`, `legacy.OIDCOption`, `legacy.WithLoginURL` |

Everything else the legacy types take stays in the root package: the cookie and session
options (`WithCookieName`, `WithSessionTimeout`, `WithSessionTableName`, ...), the
password options (`AutoUpgradeHashes`, `HashAlgorithm`), the role sync slot (`RoleSync`,
`DisableRoleSync`), `NoCustomData`, `ImpersonationRequest` and the impersonation
options. The storage constructors stay in `sessionstorage` (`NewSpannerPasswordAuth`,
`NewPostgresPassword`, `NewSpannerOIDC`, `NewPostgresOIDC`, `WithOIDCUsers`, the
per-driver custom data configurations) and carry the same deprecation.

Four smaller changes can reach an application on the legacy types:

- `sessioninfo.NewSessionRequest` has no `Hd` and `Sub` fields any more; they were the
  Google type's. The verified claims are still `req.Claims`, and on `Auth`
  `req.Identity` carries the identity's method, connection, subject, email and claims.
- `sessioninfo.SessionData` is no longer comparable, because it carries the session's
  auth events. Code that compared two values with `==` compares the fields it means.
- The mock packages `mock/mock_azureoidc` and `mock/mock_googleoidc` are gone. The
  Azure and Google authenticators are mocked in `mock/mock_azure` and
  `mock/mock_google`, and `MockUserRoleManager` lives in `mock/mock_signin`.
- The store's table-name setters (`SetSessionTableName`, `SetUserTableName`,
  `SetOIDCUserTableName` on `sessionstorage.BaseStore`) return an error: every table
  name is validated where it is set, and a name that is not a plain identifier is
  refused. Code that calls a setter directly checks the error; the session options are
  the usual way, and the constructor reports a refused name under the option's name.

An application on the v0.12 Google type has no legacy copy to move to; see "From the
Google type of v0.12" below.

## 2. Move to Auth

### What an Auth application looks like

One `Auth` serves every sign-in method. The application builds the store, constructs
the `Auth` with its sign-in policy, registers the methods it offers, and wires routes
from the handlers each registration returns. The README's "Auth sessions (multiple
sign-in methods)" section is the reference; this is the shape:

```go
events, err := sessionstorage.NewAuthEventsTable("SessionAuthEvents")
store := sessionstorage.NewSpannerAuth(client, sessionstorage.WithAuthEvents(events)).
    WithCustomSessionData(sessionData). // optional: the README's "Custom session data"
    WithCustomUserData(userData)        // optional: the README's "Custom user data"

auth, err := session.NewAuth[MyData, UserData](store, cookieKey,
    session.WithCookieName("app_auth"), session.WithSessionTimeout(8*time.Hour))

password := session.PasswordSignIn(auth, session.HashAlgorithm(alg))
entra := azure.SignIn(auth, "azure", nil, &azure.Config{ // nil: the standard account rule decides first sign-ins
    Tenants: azure.Tenant(tenantID), ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL, // the tenant the v0.12 issuer named
    RoleSync: signin.RoleSync(userRoleManager), LoginURL: "/login",
})

r.Use(auth.StartSession, auth.SetXSRFToken)
r.Get("/api/user/authenticated", auth.Authenticated())
r.Get("/api/user/login", entra.Login())
r.Get("/api/user/callback", entra.Callback())
r.Get("/api/user/logout/frontchannel", entra.FrontChannelLogout())
r.Group(func(r chi.Router) {
    r.Use(auth.ValidateXSRFToken)
    r.Post("/api/user/session", password.Login())
    r.Group(func(r chi.Router) {
        r.Use(auth.ValidateSession)
        r.Post("/api/user/logout", auth.Logout())
        r.Post("/api/user/password", password.ChangeUserPassword())
    })
})
```

Three things every move shares:

- **Users are managed by ID through `auth.API()`**: `CreateSessionUser`,
  `ChangeSessionUserUsername`, `SetSessionUserPassword`, `DeactivateSessionUser`,
  `ActivateSessionUser`, `DeleteSessionUser`, `DestroyUserSessions`, `Identities` and
  `UnlinkIdentity`. The `Auth` has no user-management handlers of its own: the
  application writes them over the API and guards them, as it guarded the callers of
  the legacy handlers.
- **An account rule of the application's own is optional.** The Entra and Google
  methods apply a standard rule to an identity's first sign-in (`Config.Accounts`):
  members of the directory get an account under their sign-in name by default, or only
  pre-created users are linked with `signin.InvitedUsersOnly`. A rule given to `SignIn`
  (`azure.AccountRule`, `google.AccountRule`) is for what the standard rule cannot know,
  and may hand over to it with `signin.Standard()`.
- **A sign-in policy is optional.** Without one, a valid credential or a resolved
  identity signs in on the library's checks, which is v0.12's behaviour. An
  application's own rule (`auth.SetSignInPolicy(rule)`) can deny a sign-in or hold it
  for its MFA step (`signin.RequireMFA`), which the legacy types could not express, and
  it decides a session the application starts (`StartAuthenticatedSession`) as well:
  there is no session start that skips it.

### From the legacy password type

**Schema.** Apply `schema/<backend>/auth/migrations` to the group. The base set is
already there; the auth set adds `UserId`, `AuthenticatedAt`, `ProviderSessionId` and
`ProviderSessionIssuer` to the sessions table and creates `SessionIdentities`, `SessionAuthEvents` and
`SessionPendingSignIns`. Nothing is backfilled: `Auth` refuses a session row without a
`UserId`, so each person signs in once after the cutover. To keep the live sessions
instead, give them their user by username before the cutover:

```sql
-- PostgreSQL
UPDATE "Sessions" s SET "UserId" = u."Id" FROM "SessionUsers" u
    WHERE s."UserId" IS NULL AND s."Username" = u."Username";

-- Spanner
UPDATE Sessions s SET UserId = (SELECT u.Id FROM SessionUsers u WHERE u.Username = s.Username)
    WHERE s.UserId IS NULL AND EXISTS (SELECT 1 FROM SessionUsers u WHERE u.Username = s.Username);
```

**Code.**

| Legacy password type | Auth |
| --- | --- |
| `legacy.NewPasswordAuth[S, U](sessionstorage.NewSpannerPasswordAuth(client, storeOptions...), cookieKey, passwordOptions...)` | `session.NewAuth[S, U](sessionstorage.NewSpannerAuth(client, storeOptions...), cookieKey, options...)` (and `auth.SetSignInPolicy(policy)` when the application has one), then `password := session.PasswordSignIn(auth, passwordOptions...)` |
| `sessionstorage.WithSpannerCustomSessionData(cfg)`, `WithPostgresCustomSessionData(cfg)` | `store.WithCustomSessionData(cfg)` with `cfg` from `sessionstorage.NewCustomSessionData(table, resolve)`; the resolver's transaction type picks the driver |
| `sessionstorage.WithSpannerCustomUserData(cfg)`, `WithPostgresCustomUserData(cfg)` | `store.WithCustomUserData(cfg)` with `cfg` from `sessionstorage.NewCustomUserData[U](table)`, which fits either driver |
| `auth.Login()`, `auth.ChangeUserPassword()` | `password.Login()`, `password.ChangeUserPassword()` |
| `auth.CreateUser()`, `DeactivateUser()`, `ActivateUser()`, `DeleteUser()`, `ChangeUsername()` (the handlers that read `RouterSessionUserID`) | The application's handlers over `auth.API().CreateSessionUser`, `DeactivateSessionUser`, `ActivateSessionUser`, `DeleteSessionUser` and `ChangeSessionUserUsername` |
| `API().Login(ctx, w, username, password)` | `API().ValidateCredentials(ctx, username, password)` returns the user ID; then `API().StartAuthenticatedSession(ctx, w, userID, []sessioninfo.AuthEvent{{Method: sessioninfo.MethodPassword}})` |
| `API().StartAuthenticatedSession(ctx, w, username, data...)` | `API().StartAuthenticatedSession(ctx, w, userID, events, data...)` |
| `API().DestroyAllUserSessions(ctx, username)` | `API().DestroyUserSessions(ctx, userID)` |
| `API().ChangeSessionUserHash(ctx, userID, hash)` | `API().SetSessionUserPassword(ctx, userID, password)`, which hashes the password and destroys the user's sessions |

### From the legacy Azure type

**Schema.** At the cutover, apply `schema/<backend>/auth-from-oidc/migrations` to the
group, four steps:

1. `000001_SessionUsers` creates the users table, as the base set does.
2. `000002_Auth` adds the Auth columns and tables. `OidcSid` becomes the nullable
   `ProviderSessionId`, renamed on PostgreSQL (the ids stay) and dropped and re-added on
   Spanner (the ids are lost), beside the new `ProviderSessionIssuer`, which the live
   legacy sessions have no value for. A front-channel logout matches the issuer and the
   id, so on both backends it cannot reach a legacy session until the person signs in
   again; the application's own logout still ends it. Step 4 gives them their user.
3. `000003_SessionPendingSignIns` creates the pending sign-ins table.
4. `000004_OIDCUsersBackfill` copies the OIDC user anchor's rows into `SessionUsers`
   under the same ids, creates one Azure identity per row (`Method` `azure`,
   `Connection` from `Tid`, `Subject` from `Oid`) and gives the live sessions their
   `UserId` by username. A group that never enabled the anchor removes this step's
   statements. Two anchor rows whose usernames casefold alike stop the backfill: resolve
   them first.

The anchor table stays. Drop it in the release after the cutover, once nothing can roll
back to the legacy type:

```sql
-- PostgreSQL
DROP TABLE "OIDCUsers";

-- Spanner
DROP INDEX OIDCUsersByTidOid;
DROP TABLE OIDCUsers;
```

A custom user data table keyed by the anchor keeps its rows, since the ids are the same.
Point its foreign key at the users table in the same window, with the constraint names
your DDL gave it:

```sql
-- PostgreSQL
ALTER TABLE "OIDCUserData"
    DROP CONSTRAINT "OIDCUserData_UserId_fkey",
    ADD CONSTRAINT "OIDCUserData_UserId_fkey" FOREIGN KEY ("UserId") REFERENCES "SessionUsers" ("Id") ON DELETE CASCADE;

-- Spanner
ALTER TABLE OIDCUserData DROP CONSTRAINT FK_OIDCUserData_OIDCUsers;
ALTER TABLE OIDCUserData ADD CONSTRAINT FK_OIDCUserData_SessionUsers FOREIGN KEY (UserId) REFERENCES SessionUsers (Id) ON DELETE CASCADE;
```

**Code.**

| Legacy Azure type | Auth |
| --- | --- |
| `legacy.NewOIDCAzure[S, U](sessionstorage.NewSpannerOIDC(client, sessionstorage.WithOIDCUsers(), storeOptions...), session.RoleSync(m), cookieKey, issuerURL, clientID, clientSecret, redirectURL, legacy.WithLoginURL(url))` | `session.NewAuth[S, U](sessionstorage.NewSpannerAuth(client, storeOptions...), cookieKey)` (and `auth.SetSignInPolicy(policy)` when the application has one), then `entra := azure.SignIn(auth, "azure", nil, &azure.Config{Tenants: azure.Tenant(tenantID), ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL, RoleSync: signin.RoleSync(m), LoginURL: url})` |
| `oidc.Login()`, `oidc.CallbackOIDC()`, `oidc.FrontChannelLogout()` | `entra.Login()`, `entra.Callback()`, `entra.FrontChannelLogout()` |
| `issuerURL`, `https://login.microsoftonline.com/<tenant id>/v2.0` | `Tenants: azure.Tenant("<tenant id>")`: the slot names the tenant, and the authority stays `https://login.microsoftonline.com` unless `Config.Authority` says otherwise; `azure.TenantOfIssuer(issuerURL)` reads a v0.12 issuer into both. The slot also takes several tenants, any tenant or Microsoft personal accounts (the README's "Microsoft Entra ID OIDC") |
| The anchor's just-in-time provisioning (`WithOIDCUsers`) | The registration's standard account rule, members of the directory: after the backfill every person the anchor knew is linked, so it provisions new people only, under `preferred_username` as the anchor did. A guest of the tenant is refused (`guest_account`), where the anchor provisioned them |
| The custom user data login hook (`NewSpannerCustomUserData(table, hook)`) | `sessionstorage.NewCustomUserData[U](table)` has no hook. A new person's row is written by a custom rule's `signin.Provision` in `onProvisioned`, in the sign-in's transaction (capture the transaction in the rule's closure), as below. A refresh from the claims on every sign-in moves to the sign-in policy, which runs on every sign-in with the transaction, `req.Identity` and `req.Claims` |
| The custom session data resolver over `req.Claims` | The same resolver, through `NewCustomSessionData`. `req.Claims` is still the raw verified claims; `req.Identity` is the decoded identity and `req.UserID` the user |
| `API().OIDCUser(ctx, id)`, `API().OIDCUserByKey(ctx, tid, oid)` | `API().Identities(ctx, userID)` lists a user's identity links; the `(tid, oid)` pair is the Azure identity's `(Connection, Subject)` |

`Tenants` is the organization slot: one tenant as above, several
(`azure.Tenants(azure.Tenant(id), azure.NamedTenant(id, name))`), any tenant
(`azure.AnyTenant()`) or Microsoft personal accounts (`azure.PersonalAccounts()`). The
README's "Which accounts may sign in" under "Microsoft Entra ID OIDC" has the shapes, what
each stores as the link's tenant key and which account rules each takes. Several
tenants, any tenant and personal accounts need an app registration that admits accounts
in any organizational directory (and personal accounts when the slot does), and role
synchronization stays with one tenant.

A custom rule is needed only when a first sign-in must write the application's own
rows, as the custom user data login hook did; it stands in for the anchor and the hook:

```go
func entraAccountRule(ctx context.Context, tx *spanner.ReadWriteTransaction, id *azure.Identity) (*signin.Resolution, error) {
    // Every person the anchor knew was linked by the backfill, so this runs for a
    // first sign-in only. The anchor provisioned them under preferred_username.
    if id.Guest {
        return signin.Reject(sessioninfo.RefusedGuestAccount), nil
    }

    return signin.Provision(&signin.NewUser{Username: id.PreferredUsername},
        func(ctx context.Context, userID ccc.UUID) error {
            // What the custom user data login hook wrote on a first login, in the
            // sign-in's transaction (tx) against the application's own tables.
            return writeProfile(ctx, tx, userID, id.Email, id.Name)
        }), nil
}
```

### From the Google type of v0.12

`OIDCGoogle` shipped in v0.12 only and has no legacy copy. Its storage
(`NewSpannerGoogleOIDC`, `NewPostgresGoogleOIDC`) and its migration set
(`schema/*/oidc-google`) are gone with it, and there is no upgrade set for that layout.
Register the method on an `Auth`:

```go
workspace := google.SignIn(auth, "google", nil, &google.Config{ // nil: the standard account rule decides first sign-ins
    ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
    Workspaces: google.Workspace("example", "example.com"), // the application's name for the Workspace (a key) and its domains
    RoleSync:   google.RoleSync(userRoleManager, "app-myapp-", google.DirectGroups()),
    LoginURL:   "/login",
})
```

`Workspaces` is the organization slot: one Workspace as above, several
(`google.Workspaces(...)`), any Workspace (`google.AnyWorkspace()`) or any Google
account (`google.AnyGoogleAccount()`); the README's "Which accounts may sign in" has the
shapes and what each writes as the link's connection. The v0.12 type's hosted domain
is the Workspace's domain here, and the Workspace's name is the connection every link
carries.

`session.GoogleRoleSync`, `DirectGroups`, `NestedGroups`, `ParseGroupLookup` and
`GroupLookup` are `google.RoleSync`, `google.DirectGroups`, `google.NestedGroups`,
`google.ParseGroupLookup` and `google.GroupLookup`.

For the schema, start the group on the base and auth sets, under the group's table
names or after dropping the v0.12 tables: the sessions end, and the standard account
rule provisions each person at their first sign-in. There is no upgrade set and no backfill for the
v0.12 Google tables.

### Table names

An application whose tables are named per auth group applies the sets under its names
(copy the files and rename the tables, indexes and constraints) and tells the `Auth`:
`WithSessionTableName`, `WithUserTableName`, `WithIdentitiesTableName` and
`WithPendingSignInsTableName` on `NewAuth`, `NewAuthEventsTable(name)` and
`NewImpersonationTable(name)` on the store. Every name must be a plain identifier (a
letter or underscore, then up to 127 letters, digits or underscores); any other is
refused at construction under the option's name. Keep the users table's unique index named
after the table as the shipped DDL does (`<UsersTable>_NormalizedUsername_idx` on
PostgreSQL, `<UsersTable>ByNormalizedUsername` on Spanner): the drivers read a username
conflict by that name.

### Behaviour that differs

- **Front-channel logout** is keyed by the provider's session id, the `sid` Entra sends,
  and ends the sessions whose sign-in carried it, impersonations started from them
  included; a request naming another issuer in `iss` is refused. The legacy type ended
  every session carrying the username.
- **Which tenants sign in** is the registration's `Tenants` slot: the one tenant the
  v0.12 issuer named, or several, any tenant or Microsoft personal accounts. A token of
  a tenant outside the slot is refused (`unlisted_tenant`, `personal_account`) before
  any user is resolved, and under every shape but one tenant the library checks the
  token's issuer against its tenant itself. Under the `skipAuth` build tag the
  simulated login asserts the registration's first listed tenant, where v0.12 asserted
  one fixed tenant, so a development database keyed on the fixed tenant sees each
  simulated person as new.
- **Refusal codes.** The login page needs a sentence for the codes `Auth` adds:
  `identity_rejected`, `policy_denied`, `user_disabled`, `pending_expired`,
  `no_email`, `not_invited`, `guest_account`, `unlisted_tenant` and `personal_account`.
- **The pending flow** (`?pending=confirmation` or `?pending=mfa` on the login page)
  exists only when an account rule or the policy asks for it. The standard rules ask
  for a confirmation when a pre-created user under the sign-in name has a password;
  without such users, without a policy that answers `signin.RequireMFA`, and with a
  custom rule that never answers `signin.Confirm`, no page is needed for it.
- **Linking across connections.** A custom rule's `signin.Link(userID, false)` is
  refused for a user who has a password (confirm with `signin.Confirm`) and for a user
  without one when the identity comes through another connection than the ones that
  user already signs in through; `trusted` links in both cases. A standard rule's match
  of a pre-created user is such an untrusted link. The v0.12 types never linked, so
  this only reaches rules written for `Auth`.
- **Role synchronization** is unchanged.

### Rolling back

- **A password group.** The legacy password type names none of the auth set's columns
  and tables, so it keeps serving the group on the upgraded schema; the sessions `Auth`
  established are ordinary rows under their usernames to it. The set's down migrations
  remove the columns and tables when they are not wanted.
- **An Azure group.** The set's down migrations restore the legacy layout, and the
  anchor's rows were copied, not moved, so the legacy type resumes with them. On
  PostgreSQL, step 2's down migration drops `ProviderSessionIssuer`, turns
  `ProviderSessionId` back into `OidcSid` and fills the rows that have none (sessions
  other methods established) with an empty string; on Spanner `OidcSid` comes back empty
  for every row. The legacy type reads
  `OidcSid` only for its front-channel logout, so the sessions stay but a logout cannot
  reach them. Roll back before dropping the anchor table.

## Time columns

v0.13 moves the ownership of "now" from the library to the database. Every column that
records when something happened is written with the database's time: on Spanner the
commit timestamp (`spanner.CommitTimestamp` in a mutation, `PENDING_COMMIT_TIMESTAMP()`
in DML), on PostgreSQL the transaction time (`now()`). The columns are a session's
`CreatedAt`, `UpdatedAt` and `AuthenticatedAt`, an auth event's `OccurredAt`, an
impersonation record's `StartedAt` and `EndedAt`, an identity link's `CreatedAt` and
`LastUsedAt`, a pending sign-in's `CreatedAt` and `ConsumedAt`, and the OIDC user
anchor's `CreatedAt` and `UpdatedAt`. A deadline (`ExpiresAt`) is still the
application's: computed from its clock and written as given. Earlier versions wrote
`time.Now()` into all of them, which Spanner refuses on a commit-timestamp column when
the host clock runs ahead of its own ("Cannot write timestamps in the future"), and
which gave the rows of one transaction several times.

**On Spanner the columns must allow commit timestamps**, or every write to them fails.
Each shipped set gained a migration that marks its columns (`ALTER TABLE … ALTER COLUMN
… SET OPTIONS (allow_commit_timestamp = true)`). A group applies the migrations of the
sets it uses, in the deploy that upgrades the library:

| Set | Migration | Columns |
| --- | --- | --- |
| `schema/spanner/migrations` | `000003_CommitTimestamps` | `Sessions.CreatedAt`, `UpdatedAt` |
| `schema/spanner/oidc/migrations` | `000004_CommitTimestamps` | `Sessions.CreatedAt`, `UpdatedAt`; `OIDCUsers.CreatedAt`, `UpdatedAt` |
| `schema/spanner/impersonation/migrations` | `000002_CommitTimestamps` | `SessionImpersonations.StartedAt`, `EndedAt` |
| `schema/spanner/auth/migrations` | `000003_CommitTimestamps` | `Sessions.AuthenticatedAt`; `SessionIdentities.CreatedAt`, `LastUsedAt`; `SessionAuthEvents.OccurredAt`; `SessionPendingSignIns.CreatedAt`, `ConsumedAt` |
| `schema/spanner/auth-from-oidc/migrations` | `000005_CommitTimestamps` | the auth set's columns; the `oidc` set's `000004` covers the sessions and anchor tables |

This reaches the legacy types too: step 1 above is an import edit on PostgreSQL, and
on Spanner also the base (or `oidc`) set's migration and the impersonation set's. An
application whose tables are named per group, or whose sessions table was written by
hand, marks the same columns under its names. The option is set on a populated table
without rewriting it, a row deletion policy on the column is unaffected, and a column
that already carries the option (the ccc schema convention) needs nothing. A group that
upgrades from the legacy Azure layout applies the `oidc` set through `000004` before
`auth-from-oidc`, so the anchor table is still there to mark; it is dropped in the
release after, as before.

Nothing changes on PostgreSQL: `now()` needs no DDL.

**Rolling back.** The down migrations clear the option. They are not needed to run a
v0.12 driver, which writes plain values and keeps working against a marked column as
before, so the option can also stay.

**What an application sees.** `sessioninfo.AuthEvent.At` is zero on an event the
application hands the library (`StartAuthenticatedSession`, `CompletePending`,
`AppendAuthEvent`) when the event happens now, and the database stamps it; an event
that happened earlier carries its time, which is stored as given and must not be later
than the database's clock. An impersonation's `StartedAt` and an identity link's
`CreatedAt` and `LastUsedAt`, read back, are the database's. The rows one write stores
agree exactly: a session's `CreatedAt`, `UpdatedAt` and `AuthenticatedAt`, its events'
`OccurredAt` and its record's `StartedAt` are one time, and a revocation stamps every
session and record it touches with one time.

## Checking the upgrade

The library proves the upgrade set on both backends in its driver conformance suite
(`TestAuth/the upgrade from the legacy Azure layout…`: the shipped `oidc` set with a
seeded anchor, upgraded by `auth-from-oidc`), and the seam suite runs an `Auth`
application on PostgreSQL and the Spanner emulator:

```sh
go test -run TestAuth ./sessionstorage/internal/...
go test -run TestAuthSeams ./internal/e2e
```

The proof that an application's own rows came through is its own test on a copy of its
database upgraded with the set: count `SessionUsers` against the anchor, and read a row
of the custom user data table through its new foreign key.
