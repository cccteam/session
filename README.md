# Session

## Overview

The Session repository is designed to handle the management of user sessions, including authorization, storage, and expiration. It provides a framework for managing sessions across different databases and supports multiple login types.

## Features

- `Session Management`: Efficient handling of user session creation, storage, and expiration.
- `Database Support`: Seamless integration with multiple databases.
  - PostgreSQL
  - Google Cloud Spanner
- `Auth Sessions`: One session that password, Azure, Google Workspace and WorkOS SSO sign-in can all establish, with accounts, explicit identity links, pending confirmation and MFA. See the "Auth sessions (multiple sign-in methods)" section.
- `Login Types`: Supports multiple authentication methods.
  - Azure OIDC
  - Google Workspace OIDC (restricted to one hosted domain — see the "Google Workspace OIDC" section)
  - Username/Password
  - Preauth (trust-the-caller stepping-stone sessions)
- `Custom Session Data`: App-defined data attached to each session, resolved atomically at session creation and available to every request. See the "Custom session data" section.
- `Custom User Data`: App-defined durable data attached to the user record — it survives logout, expiry, and regeneration, and dies with the user. See the "Custom user data" section.
- `OIDC User Anchor`: An optional library-managed durable user record for OIDC logins, keyed by the provider's immutable identity — the `(tid, oid)` claim pair on Azure, the `sub` claim on Google. See the "OIDC user anchor" section.
- `Login Refusal Codes`: A refused OIDC login returns the browser to the login page with a code, never with text; the page maps the code to a sentence it holds itself. See the "Login refusal codes" section.

All session types are generic over two data axes: `PasswordAuth[SessionData, UserData]`,
`OIDCAzure[SessionData, UserData]`, `OIDCGoogle[SessionData, UserData]`, and
`Preauth[SessionData]` (Preauth has no user record, so no user-data axis). An
application that uses neither instantiates with the `NoCustomData` sentinel:
`session.NewPasswordAuth[session.NoCustomData, session.NoCustomData](storage, cookieKey)`.

## Schema

The DDL for every table the library owns ships as golang-migrate files under
`schema/spanner/` and `schema/postgresql/`: `migrations` (sessions and password-auth
users), `oidc` (Azure OIDC), `oidc-google` (Google Workspace OIDC), `impersonation`, and
`accounts` (Auth sessions: session accounts, identity links and auth events).

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

## Auth sessions (multiple sign-in methods)

`Auth[SessionData, UserData]` is one session that any registered sign-in method can
establish: password, Microsoft Entra ID (Azure), Google Workspace and WorkOS SSO. An
application mounts one cookie, one session table and one middleware chain, and every
session belongs to an **account**, a `SessionUsers` record, by its ID. The password
method checks the account's password; an external method produces a verified
**identity** that is linked to an account through the identities table, keyed by
`(method, connection, subject)` and **never by email**.

| Method | Registration → handlers | Identity key (connection, subject) | Login parameters | Roles |
| --- | --- | --- | --- | --- |
| `password` | `PasswordSignIn(auth, options...)` → `*PasswordMethod`: `Login`, `ChangeUserPassword` | account ID | JSON `{"username", "password"}` | — |
| `azure` | `AzureSignIn(auth, roleSync, issuer, clientID, secret, redirectURL, ...)` → `*AzureMethod`: `Login`, `Callback`, `FrontChannelLogout` | (`tid`, `oid`) | `?returnUrl=` | `RoleSync(manager)` or `DisableRoleSync()` |
| `google` | `GoogleSignIn(auth, roleSync, clientID, secret, redirectURL, hostedDomain, ...)` → `*GoogleMethod`: `Login`, `Callback` | (`""`, `sub`) | `?returnUrl=` | `GoogleRoleSync(...)` or `DisableRoleSync()` |
| `workos` | `WorkOSSignIn(auth, apiKey, clientID, redirectURL, ...)` → `*WorkOSMethod`: `Login`, `Callback` | (`connection_id`, `idp_id`) | `?organization=` (required), `?returnUrl=` | never synchronized |

### Storage and schema

Apply the base migrations (`schema/*/migrations`) and the accounts migrations
(`schema/*/accounts/migrations`: `Sessions.UserId` and `AuthenticatedAt`,
`SessionIdentities`, `SessionAuthEvents`), plus `impersonation` if you use it. Build the
storage with `NewSpannerAccounts` / `NewPostgresAccounts`; any external method needs an
identities configuration, which carries the application's **account resolver** (what to
do with an identity that is not linked yet: `LinkIdentity`, `ProvisionAccount`,
`RequireConfirmation` or `RejectIdentity`) and its optional **sign-in policy** (`AllowSignIn`,
`RequireMFA` or `DenySignIn`, for every method once the account is known). Each receives
its transaction (`*spanner.ReadWriteTransaction` or `pgx.Tx`), so it can read and write
the application's own rows; on Spanner it may run more than once when the transaction
retries, so it must not have side effects outside it.

A sign-in runs in two transactions, the same on Spanner and PostgreSQL:

1. **Account resolution** (external methods): a linked identity is its account's;
   otherwise the account resolver runs and its outcome is applied: the link, or the new
   account, its link and the rows `Resolution.OnProvisioned` writes.
2. **Decision and session**: the account is read (a disabled one is refused), the
   sign-in policy runs, and the session row is inserted with its auth events and custom
   session data.

Each transaction **commits unless a hook or the storage returns an error**. A
`RejectIdentity`, `RequireConfirmation`, `DenySignIn` or `RequireMFA` answer is not an
error: it commits the hook's own writes (a record of a refused sign-up, an audit row) and
writes no session. Because the resolution has committed by the time the policy runs:

- the policy (and the custom session data resolver) **reads the account a sign-in just
  provisioned** and the rows `OnProvisioned` wrote, on both backends;
- `req.Account` (`*sessioninfo.SignInAccount`) tells them which account was resolved and
  how: `Source` is `AccountNamed` (password), `AccountExistingLink`, `AccountNewLink` or
  `AccountProvisioned` (`req.Account.Provisioned()`), with the link's `Tenant`;
- **an account the resolver provisioned stays, linked, when the policy then denies the
  sign-in or holds it for MFA**; the next sign-in goes through the link and the policy
  decides again. Return `RejectIdentity` from the resolver when the account must not be
  created at all. A hook error rolls back its own transaction only: an `OnProvisioned`
  failure leaves no account, while a policy error leaves a provisioned account in place.

```go
identities, err := sessionstorage.NewSpannerIdentities("SessionIdentities", resolveAccount, signInPolicy)
events, err := sessionstorage.NewAuthEventsTable("SessionAuthEvents")
store := sessionstorage.NewSpannerAccounts(client,
    sessionstorage.WithSpannerIdentities(identities),
    sessionstorage.WithAuthEvents(events))

auth, err := session.NewAuth[MyData, session.NoCustomData](store, cookieKey,
    session.WithCookieName("partner_auth"),
    session.WithIdentityLinked(notifyLinked), // called after every identity link
    session.WithPendingHook(onPending),       // called when a sign-in becomes pending
    session.WithPendingTimeout(10*time.Minute),
    session.WithPendingCookieName("auth-pending"),
)

// Register the sign-in methods before serving; each returns its own handlers.
password := session.PasswordSignIn(auth) // *session.PasswordMethod
workos := session.WorkOSSignIn(auth, cfg.WorkOSAPIKey, cfg.WorkOSClientID, cfg.SSORedirectURL,
    session.WithLoginURL("/login")) // *session.WorkOSMethod
```

`NewAuth` refuses the OIDC-only storage features (`WithOIDCUsers`, the custom user data
login hook).

### Registering sign-in methods

A sign-in method is registered on the `Auth`, and its registration returns the method's
own handlers; routes are wired from that value. The handler is the proof of
registration: a method that was not registered has no handlers to wire, and each method
is its own type, so a handler exists only on the method it belongs to
(`FrontChannelLogout` only on `*AzureMethod`). A registered method with no route is
harmless.

Registration is refused, with a panic, in one place, the way `http.ServeMux` refuses a
duplicate pattern: these are wiring mistakes, found when the application starts.

- **A method registered twice** on one `Auth`.
- **A method registered once the `Auth` is in use**: after it has served a request
  through any of its handlers or middleware, or read its methods to check or hash a
  password through its API (`CreateSessionUser` before `PasswordSignIn(auth,
  HashAlgorithm(...))` would have hashed with the default). Register every method, then
  build the router and serve.
- **An external method on storage without identities**
  (`sessionstorage.ErrIdentitiesNotConfigured`, which the panic value wraps).
- **A misconfigured method**: Azure or Google without its role sync slot, Google without
  its hosted domain, cookie or session options passed to `PasswordSignIn` instead of
  `NewAuth`.

### Routes

```go
r.Use(auth.StartSession, auth.SetXSRFToken)
r.Get("/api/user/authenticated", auth.Authenticated())
r.Get("/api/user/sso/login", workos.Login())       // ?organization=…&returnUrl=…
r.Get("/api/user/sso/callback", workos.Callback())
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
`WithLoginURL` (default `/login`).

| Outcome | External `Callback()` | `password.Login()` |
| --- | --- | --- |
| Session established (new session ID) | `302 <returnUrl>` (default `/`) | `200 {"mfaIsRequired": false}` |
| Waits for the account's password | `302 <LoginURL>?pending=confirmation[&returnUrl=<path>]`, or the pending hook's URL | — |
| Waits for the application's MFA | `302 <LoginURL>?pending=mfa[&returnUrl=<path>]`, or the pending hook's URL | `200 {"mfaIsRequired": true[, "redirectUrl"]}` |
| Refused | `302 <LoginURL>?code=<code>` | `401 {"message", "code"}` (403 for a forbidden cause) |

- `returnUrl` is only ever a path in the application. An external `Login()` whose
  `returnUrl` is an absolute URL, `//host` or `/\host` is refused with **400**, and the
  callback sanitizes it again. A WorkOS `Login()` without `organization` is also 400.
- `pending` is the login page's routing marker. The page reads the pending identity from
  `Pending().Status()`: `200 {"reason", "email", "expiresAt", "returnUrl"}`, `404` when
  there is none, `401 {"code": "pending_expired"}` once it has expired or been used.
- **Confirmation** (`reason` `confirmation`): the page asks for the existing account's
  password and posts `{"password"}` to `Pending().ConfirmWithPassword()`: `200
  {"mfaIsRequired": false}` (linked, the hook called, signed in; go to `returnUrl`),
  `200 {"mfaIsRequired": true}` (linked, but the policy wants MFA: the pending identity
  remains with reason `mfa`), `401` for a wrong password (the pending identity remains),
  `409` when the pending identity waits for MFA instead.
- **MFA** (`reason` `mfa`): the application runs its own step and calls
  `auth.API().CompletePending(ctx, w, sessioninfo.AuthEvent{Method: "email-otp"})`, which
  starts the session (the policy is not asked again; the account is resolved afresh and
  must be the one it waited on) and records the sign-in's events followed by the step's.
  The pending identity always names its account (`UserID`, `Username`), including one the
  sign-in has just provisioned, which exists by then.
- `Pending().Cancel()` discards the pending identity.
- **The pending hook** (`WithPendingHook`) runs when `password.Login()`, an external
  `Callback()` or `Pending().ConfirmWithPassword()` has just held a sign-in, after the
  pending identity is stored and its cookie set. It receives the
  `*sessioninfo.PendingIdentity` (reason, account, the identity with its email, expiry,
  return path), so the application can send its MFA code and choose the next page:

  ```go
  func onPending(ctx context.Context, w http.ResponseWriter, r *http.Request, p *sessioninfo.PendingIdentity) (string, error) {
      if p.Reason != sessioninfo.PendingMFA {
          return "", nil // the default: <LoginURL>?pending=confirmation
      }
      if err := mfa.SendCode(ctx, p.UserID.UUID); err != nil {
          return "", err // the pending identity is discarded and the sign-in fails
      }

      return "/account/mfa", nil
  }
  ```

  The callback redirects to the URL it returns, and the JSON handlers answer it as
  `"redirectUrl"`; an empty URL keeps the default. The hook may instead write the response
  itself, and nothing more is written. An error discards the pending identity and fails
  the sign-in (`?code=internal_error` on a redirect). The hook changes nothing about the
  pending identity (its cookie, its timeout; the session ID is regenerated when it
  completes). The URL is the application's own: never build it from request input. The
  `AuthAPI` methods never call the hook: `CompletePending` and
  `ConfirmPendingWithPassword` return a `*sessionstorage.PendingSignInError` instead.
- The codes are the `sessioninfo.LoginRefusalCode`s of the "Login refusal codes"
  section, including the resolver's and policy's own; text never travels.

### What a pending identity is

A pending identity is a verified identity waiting for its confirmation or MFA: a preauth
stepping-stone row in the session table (no account, never authenticated) and the
`auth-pending` cookie, encrypted and authenticated with the cookie key, that carries the
identity, the account it waits on, the steps so far and the return path, bound to that
row. Completing, cancelling or replacing it expires the row, so a copied cookie completes
nothing, and the row never validates as a session. The row is inserted with
`ReasonPendingIdentity`, for which the custom session data resolver is **not** called: it
has no account and carries no custom data. An identity's claims must fit the cookie once
compressed (about 2.8 KB): a larger one is refused with `internal_error`.

### Every session

- **The session ID is regenerated** at every sign-in, confirmation and MFA completion:
  the cookies are written only once the session row, its auth events and role
  synchronization have succeeded.
- **The account is loaded by `UserId` on every request.** `ValidateSession` refuses a
  session with no account or whose account is missing or disabled; the account is
  `sessioninfo.UserFromCtx(ctx)`. The session's account, authentication time and auth
  events are on the context's `*sessioninfo.SessionData`
  (`sessioninfo.DataFromCtx(ctx)`): `UserID`, `AuthenticatedAt`, `AuthEvents`.
- **Custom session data** is resolved in the transaction that inserts the session, after
  the account resolution has committed: the resolver reads the account (one just
  provisioned included) and the application's rows, and `req.Account` says how the
  account was found. It is never called for a pending identity's row.
- **Each session records how it was authenticated** in `SessionAuthEvents`: the sign-in
  method (with its connection and the IdP's `amr`), then any `link-confirmation` and MFA
  steps. `AuthAPI.StartAuthenticatedSession(ctx, w, userID, events)` starts a session the
  application authenticated itself, recording its events; the policy is not consulted.
- **Role synchronization** (Azure, Google) reconciles the roles of the account the
  identity resolved to, from the roles the provider asserted at sign-in, whenever such a
  sign-in establishes a session (including after a confirmation or MFA). A sign-in left
  with no recognized role is refused (`no_roles`) and its session expired.
- **Impersonation** works as on the other types. A user principal's session belongs to
  the impersonated account; a role principal's belongs to none. The session records an
  `impersonation` event whose connection is the actor.
- **Account management is by ID**: `ChangeSessionUserPassword`, `SetSessionUserPassword`,
  `DeactivateSessionUser` and `DeleteSessionUser` destroy the account's sessions by
  `UserId`; `DeleteSessionUser` deletes its identity links with it; `UnlinkIdentity`
  refuses an account's last means of sign-in.
- **Not yet supported**: provider-initiated (front-channel) logout.
  `AzureMethod.FrontChannelLogout()` answers 501 until the accounts schema records the
  provider's session ID.

## OIDC role synchronization

Role synchronization reconciles a user's application roles to the identity provider's
authorization signal on every OIDC login: role names sourced from the IdP are assigned
(where a role of that name exists), roles the user holds that are NOT among them are
removed, and the login is rejected unless at least one recognized role results. It is
designed for organizations that manage roles centrally in the directory. The role
names come from the provider's native mechanism — Azure delivers them in the token's
`roles` claim (App Role ↔ group assignments); Google has no such claim, so the Google
flow derives them from Google Groups membership at login (see the "Google Workspace
OIDC" section). See the `OIDCAzure` and `OIDCGoogle` godoc for the full semantics.

A membership is written where the role is held. A global role is held in the global
partition, and a domain role is held in every tenant domain, so one membership reaches
every tenant, the ones that exist today and the ones created later; the sync keeps no
list of tenants. A membership the directory does not name is removed wherever it is
held, a membership in one tenant domain included, so an application that writes its own
memberships (a tenant-specific role, say) runs with role synchronization disabled.

The `NewOIDCAzure` constructor takes a required role-sync slot that enables or disables
the feature:

```go
// Enabled: reconcile the user's memberships to the token's roles at every login.
oidcSession, err := session.NewOIDCAzure[session.NoCustomData, session.NoCustomData](
    storage,
    session.RoleSync(userRoleManager),
    cookieKey, issuerURL, clientID, clientSecret, redirectURL,
)

// Disabled (application-managed roles, or no roles at all): no roles are read,
// written, or removed at login, and the at-least-one-role gate does not apply.
oidcSession, err := session.NewOIDCAzure[session.NoCustomData, session.NoCustomData](
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
tenant domain. `RoleExists` errors must be returned, never flattened to "role missing":
the sync removes what the directory does not name, so a swallowed store error would
delete a valid membership on a transient fault.

Migrating from the shape that took a domains provider (`session.RoleSync(manager,
domainsFn)` and `session.GoogleRoleSync(manager, domainsFn, ...)`): drop the provider,
since the sync no longer keeps a list of tenants, and give the manager the
`accesstypes.PolicyScope` signatures above. Older code that passed the manager straight
to `NewOIDCAzure` wraps it in `session.RoleSync(manager)`, and
`session.DisableUserRoleManagement()` becomes `session.DisableRoleSync()`, which also
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
// Directory-driven roles: at login, the person's Google Groups are read with their own
// access token and mapped to role names by a group naming convention (see "The group
// naming convention"). DirectGroups is the default lookup; session.ParseGroupLookup
// reads the setting ("direct" or "nested") from configuration.
oidcSession, err := session.NewOIDCGoogle[session.NoCustomData, session.NoCustomData](
    storage, // sessionstorage.NewSpannerGoogleOIDC / NewPostgresGoogleOIDC
    session.GoogleRoleSync(userRoleManager, "app-myapp-", session.DirectGroups()),
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
lowercase names.

Membership is read at login through Google's Cloud Identity Groups API, with the
signing-in person's own access token. An access token is the credential that lets the
application call a Google API as that person. The library gets it by asking for one
extra OAuth scope, in addition to `openid`, `email` and `profile`:
`https://www.googleapis.com/auth/cloud-identity.groups.readonly`. A scope names one
permission the application asks the person for. The token is used for the lookup once
and never stored. No administrator credential is involved: no service account (a
Google account for software rather than a person), no domain-wide delegation (a
setting that lets such an account act as anyone in the organization), and no admin
role.

The last argument of `GoogleRoleSync` is a `session.GroupLookup`, which sets how far
the lookup reaches. It has two values:

- `session.DirectGroups()` (the default): one call. Only the groups the person is
  directly assigned to count, however the directory is nested (role groups should then
  hold people, not other groups — matching Entra's direct-only App Role resolution).
- `session.NestedGroups()`: the groups those groups are in count too, level by level,
  up to 10 levels. Each level is one round of calls to Google, so a deeply nested
  directory makes login slower. `DirectGroups` restores the one call.

`session.ParseGroupLookup(value)` reads the setting from configuration: `direct` or
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

### Identity and the other differences from Azure

| Concern                | Azure (`OIDCAzure`)                  | Google (`OIDCGoogle`)                          |
| ---------------------- | ------------------------------------ | ---------------------------------------------- |
| Username               | `preferred_username` claim           | `email` claim (`email_verified` enforced)      |
| Durable identity key   | `(tid, oid)` — oid is tenant-scoped  | `sub` alone — globally unique, never reused    |
| User anchor table      | `OIDCUsers`                          | `GoogleOIDCUsers` (`Hd`/`Username` mutable attributes) |
| Roles source           | Token `roles` claim                  | Google Groups lookup + naming convention       |
| Org restriction        | Single-tenant registration / `tid`   | Internal consent screen + `hostedDomain` (`hd`) |
| IdP-initiated logout   | `FrontChannelLogout` (`sid` claim)   | None — Google has no `end_session_endpoint` or `sid`; `Logout` destroys the local session only |

## Login refusal codes

A refused OIDC login returns the browser to the login page with the reason as a code, never
as text: `<LoginURL>?code=<code>`. The page maps the code to a sentence it holds itself and
shows nothing for a code it does not know, so nothing that arrives in the URL is ever
displayed. `LoginURL` is the login page of the surface the auth serves; both `Login` and
`CallbackOIDC` redirect there, and `code` is the only query key they write.

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
| `not_workspace_member` | `RefusedNotWorkspaceMember` | Google: the account is outside the Workspace domain logins are restricted to. |
| `email_not_verified` | `RefusedEmailNotVerified` | Google: the account's email address is not verified. |
| `no_roles` | `RefusedNoRoles` | Role synchronization left the person with no recognized role. |
| `no_email_claim` | `RefusedNoEmailClaim` | Google: the ID token carries no `email` claim. |
| `identity_rejected` | `RefusedIdentityRejected` | Auth: the account resolver rejected the identity (its own code wins when it sets one), linked an account that has a password without confirmation, or the identity resolved to another account than it waited on. |
| `policy_denied` | `RefusedByPolicy` | Auth: the sign-in policy denied the sign-in (its own code wins when it sets one). |
| `account_disabled` | `RefusedAccountDisabled` | Auth: the sign-in resolved to a disabled account. |
| `pending_expired` | `RefusedPendingExpired` | Auth: a confirmation or MFA step arrived after its pending identity expired or was used. |
| `no_email` | `RefusedNoEmail` | For an application's resolver: the external identity carries no email address where one is required. |

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
  sign-in it runs after the account resolution has committed (see "Auth sessions"), and
  never for a pending identity's row.

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

oidcSession, err := session.NewOIDCAzure[SessionClaims, session.NoCustomData](
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
| Resolver returns an error | Session creation aborts atomically: no session row, no custom row, no cookies; login fails (OIDC: redirect to the login page with a refusal code, see "Login refusal codes") |
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
| Password auth | The `SessionUsers` record's username | The record's ID | A missing or disabled user |
| Preauth | The name as given | Zero | — (trust-the-caller, as `Login` is) |
| OIDC Azure / Google | The name as given (what a login would take from the token) | Zero | — |

An impersonated OIDC session authenticates no ID token: no OIDC user anchor is upserted,
no roles are synchronized, and the configured custom session data resolver receives
`ReasonImpersonation` with no claims. The row carries no identity provider session ID,
so an identity provider logout cannot name it directly — but `FrontChannelLogout` expires
every live session carrying the *username* of the session the provider named. A provider
logout of `bob@partner.org` therefore also ends every user-principal impersonation of bob
and any foreign actor's role session borrowing bob's name. The logout itself does not end
those sessions' records; the next request on one is refused and ends its record
`Expired`. Otherwise an impersonated OIDC session ends by its hard cap, idle expiry,
`Logout`, `EndImpersonation`, `DestroyImpersonatedSession`, or
`DestroyImpersonatedSessions`.

#### Local and foreign actors

`ActorRealm` says where the actor was authenticated, and it decides what the actor's name
means in this application's session table:

| | Local actor (`ActorRealm` empty) | Foreign actor (`ActorRealm` set) |
| --- | --- | --- |
| Who | An account of this application, logged in here | Authenticated by another application or IdP |
| `SourceSessionID` | Required and verified: the actor's own live, non-impersonated session here, carrying their username. Defaults to the request's own session when the call arrives on one | Optional; the session in the source application, for correlation |
| A role principal's session | The actor's own session, narrowed to the role | A session under a borrowed name |
| Kept alive | The source session's activity is refreshed with the impersonated session's, so `EndImpersonation` can return to it | — |
| Deactivating or renaming the account named `Actor` | Includes the role session and every impersonation the actor holds (see *One name, one account*) | Never touches the role session |

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
  `DestroyAllUserSessions` all end the record with a reason (`Logout`, `Expired`,
  `Released`, `Revoked`); an OIDC `FrontChannelLogout` expires the row, and the record
  ends `Expired` on the session's next request. `API().DestroyImpersonatedSessions(ctx, actor)`, on every
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
- **Validation (password auth).** A user principal's record is looked up like any
  session's — a disabled impersonated user ends the session. A foreign actor's role
  principal has no local user: no record is looked up and `UserFromCtx` carries the
  actor's username with the zero ID, so self-referential checks (cannot delete yourself)
  go inert, correctly. A local actor's role principal is their own session, so their
  record is looked up as usual — a disabled actor's role session ends with their others.
  Preauth and OIDC validate an impersonated session exactly as any other.
- **Identity operations.** The library's own handlers refuse under impersonation:
  `ChangeUsername` and `ChangeUserPassword` always (they would alter the impersonated
  user's credentials); `CreateUser`, `DeactivateUser`, `DeleteUser` and `ActivateUser`
  when the session is masked. Each refusal is an `IdentityOperationBlocked` event.
- **One name, one account.** A role principal's session carries the actor's own username,
  in the same session table as the application's real accounts. For a *local* actor that
  name is their account, and the two username-keyed store operations treat everything
  under it as theirs: `DestroyAllUserSessions` expires their own sessions, their role
  sessions, and every impersonation they hold as a local actor under other names, ending
  the records `Revoked`; the session rename on `ChangeUsername` renames their role sessions
  and moves their live records to the new name. For a *foreign* actor the name is
  borrowed, so password auth refuses a role principal when that name is already a
  `SessionUsers` account (the actor logs in as that account, or impersonates it as a user
  principal), and the two operations never touch a session carrying a live foreign
  role-principal record — an account created later under that name cannot reach the
  actor's session either. Preauth and OIDC have no username-keyed account to collide with;
  OIDC's `FrontChannelLogout` is username-keyed all the same, and makes no exception for a
  foreign role session (see *Identity by session type*).
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
