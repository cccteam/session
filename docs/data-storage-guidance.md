# Storing Data Alongside Sessions: Guidance and Anti-Patterns

> **Status: ADOPTED** (2026-08-09, committed with the custom-session-data series).
> The taxonomy, patterns (P-n), and anti-patterns (AP-n) are the team's guidance —
> argue about them by name. Open questions (OQ-n) at the end carry their current
> direction or resolution; several are now implemented and marked as such.

## The two kinds of data

Everything an app wants to store "with the session" is one of two things, and
almost every design mistake in this space comes from confusing them:

**Session data** is ephemeral by nature. It describes *this login*, not the
person: the currently selected tenant, an impersonation context, an MFA
elevation flag, a claims snapshot taken at login. It is born when the session
is created, dies when the session dies, and is **reset when a session is
regenerated** (e.g., on password change). If losing it on regeneration feels
like data loss, it was never session data.

**User data** is durable. It describes the person across logins: provisioning
state, profile fields, preferences, the immutable identity key from an external
IdP, anything other records reference. It must survive logout, session
expiration, regeneration, and renames.

**The rule:** the custom session data table holds session data only. User data
belongs in an app-owned user table, keyed by a stable identifier. The
session-creation resolver is the *hook* for writing both (it runs inside the
session-insert transaction with the claims/user in hand), but the two kinds of
data have different *destinations*.

## What the library gives you, per auth mode

| | Username/Password | Azure OIDC | Preauth |
|---|---|---|---|
| Library user table | `SessionUsers` (UUID PK, username unique) | `OIDCUsers` (opt-in via `WithOIDCUsers()`; UUID PK, `(Tid, Oid)` unique) | none |
| Stable identity anchor | `SessionUsers.Id` (UUID) | `OIDCUsers.Id` (UUID over the immutable `(tid, oid)` pair); without the anchor, the `oid` claim via `req.Claims` | caller-defined |
| Username mutability | mutable, tracked (`ChangeSessionUserUsername` updates in place) | mutable, tracked with the anchor (login upserts `Username` in place); **untracked** without it | caller-defined |
| Custom session data | resolver + per-call (`StartAuthenticatedSession`) | resolver fed raw verified claims (`req.Claims`) and, with the anchor, `req.UserID` | caller-supplied per-call (`Preauth.API().Login()`) |
| Custom user data | per-call on `CreateSessionUser` + RMW `UpdateCustomUserData`, FK → `SessionUsers.Id` | login hook fed claims + current row (requires the anchor) + RMW, FK → `OIDCUsers.Id` | unsupported (no user record) |
| Session regeneration | on password change (custom session data re-resolved with `ReasonRegeneration`; user data untouched) | n/a today | n/a |

## Patterns

### P-1: Extend the user record off the stable key, never the username

- **Username/Password:** key app user-data tables by `SessionUsers.Id`. A
  username change updates one column in one table; everything downstream holds.
  For small extensions, the library now ships this pattern: custom user data
  (FK → `SessionUsers.Id`, per-call on `CreateSessionUser`, RMW updates).
- **Azure OIDC:** enable the library-managed anchor (`WithOIDCUsers()`) and key
  by `OIDCUsers.Id` — a surrogate UUID over the immutable `(tid, oid)` pair.
  Apps that manage their own user table instead key it by `oid` (single-tenant)
  or the composite `(tid, oid)` (multi-tenant). `oid` is immutable per user per
  tenant; it is the only rename-proof, recycle-proof anchor Azure gives us.
  Username (`preferred_username` / UPN) is a mutable *attribute* on that row —
  which is exactly how `OIDCUsers` treats it.
- **Preauth:** the library never sees claims or credentials, so the caller owns
  identity. Whatever string is passed as `username` becomes the identity for
  the session's lifetime — pass a stable identifier, or maintain the mapping
  yourself. Durable custom user data is deliberately unsupported here: keying
  it on a caller-supplied username string is AP-1.

#### OIDC key choice: `oid` alone vs `(tid, oid)` composite

What the claims mean:

- **`oid`** is the GUID of the user object in the Entra ID directory (tenant)
  that issued the token. It is immutable for the life of that object and
  unique **within that tenant**. It is the same value the Graph API reports
  as the user's object id, so it correlates across all of your apps and with
  directory tooling. (Prefer it over `sub`, which is pairwise — unique per
  user *per application* — and therefore useless for correlating anything.)
- **`tid`** is the GUID of the tenant the token was issued for.

**Single-tenant app** (all users from one directory): `oid` alone is a
sufficient primary key. `tid` is a constant, so including it in the key adds
nothing. Cheap insurance if multi-tenancy is ever plausible: store `tid` as a
plain column from day one — promoting it into the key later is then a schema
change, not a data backfill.

**Multi-tenant app** (sign-ins from multiple directories): the primary key
must be the composite `(tid, oid)`. Two reasons:

1. **Uniqueness is only guaranteed per tenant.** Microsoft's own guidance is
   that a cross-tenant user identifier is the `tid` + `oid` pair; treating
   `oid` as globally unique is relying on an accident of GUID generation, not
   a contract.
2. **The semantics are per-tenant anyway.** The same human reaching your app
   through two tenants (home tenant, or as a guest in another) presents a
   *different* `oid` per tenant. `(tid, oid)` makes each tenant-scoped
   identity its own row — which is almost always what a multi-tenant app
   wants. If the product genuinely needs "one human across tenants," that is
   an account-linking feature the app builds on top, not something any claim
   gives you.

### P-2: JIT-provision user data inside the resolver transaction

**Library-managed (OIDC):** with `WithOIDCUsers()` this pattern ships in the
box — every OIDC login upserts the `OIDCUsers` anchor inside the session-insert
transaction (provision on first login, rename-in-place, touch `UpdatedAt`), and
the custom user data login hook runs in the same transaction with the claims
and the user's current row in hand. A hook failure aborts the login atomically.

For app-owned tables, the same steps hand-rolled in the session-creation
resolver (which runs inside the same database transaction as the session
insert):

1. Look up the user row by stable key (`oid` for OIDC, `SessionUsers.Id` for
   password auth).
2. Not found → provision the row.
3. Found with a different username → **it's a rename**; update the username
   attribute in place. Continuity is preserved: no orphaned record, no cleanup
   needed, no data inherited by a future holder of the old name.
4. Found → touch last-login (or whatever bookkeeping the app wants).

A resolver failure aborts the login atomically — no session exists without its
provisioning having succeeded.

### P-3: Carry the durable key as session data

Return the stable user key (`oid`, or the user-table PK) from the resolver
as a custom session data column. Every subsequent request can then reach the
durable user record straight from the request context — no per-request
username→key lookup, and no temptation to key anything else by username.
With the OIDC anchor enabled this is one field copy: the resolver receives
`req.UserID` already populated with the `OIDCUsers` record's ID.

### P-4: Namespace usernames when multiple authorities mint them

When more than one system creates sessions in the same session-user space —
imagine a back-office app, *Dispatch*, whose support staff can open
impersonation sessions in a customer-facing app, *Waypoint* — prefix the
minted username with an authority marker that is invalid in real usernames
(e.g., `support:` — `:` cannot appear in email-format usernames). This makes
collision with a real user impossible and provenance visible in logs.

## Anti-patterns

### AP-1: Username as the primary key for durable user data (any mode, worst in OIDC)

Two failure modes, both silent:

- **Rename:** the user self-provisions under the new name; their accumulated
  record is orphaned under the old one and eventually swept by stale-user
  cleanup. That is data loss for a real person, not clutter.
- **Recycled username:** a new hire receives a departed employee's UPN before
  cleanup fires and *inherits their record* — a correctness and privacy
  failure.

With password auth this is unforced error (the UUID exists; use it). With OIDC
it was historically the path of least resistance because the library offered no
user table — the OIDC user anchor (`WithOIDCUsers()`) now removes the excuse. Note
what stays fine: username as *session plumbing* (session rows, role sync,
log attribution) is unaffected — sessions are per-login and roles re-derive
from the token on every login.

### AP-2: User data in the custom session data table

Storing profile fields, provisioning state, or the oid *only* in the session
extension table means: duplicated per login, gone on logout/expiry, reset on
regeneration, and unreachable when the user has no active session. The
regeneration semantics (see below) are not a bug to work around here — they are
the signal that the data is in the wrong place. Snapshotting a *copy* of a
claim into session data for convenience (P-3) is fine; making it the system of
record is not.

### AP-3: Populating session data outside the creation transaction

Creating a session and then back-filling its custom data in a second call
(`StartAuthenticatedSession` + `UpdateCustomSessionData`) leaves a window where
the auth cookie is live but the session's data row is absent — and if the
second call fails, a broken-but-authenticated session escapes. The atomic path
exists: pass the data at creation (per-call data on `StartAuthenticatedSession`
and `Preauth.API().Login()`, or the configured resolver), written in the same
transaction as the session insert. `UpdateCustomSessionData` is for *changing*
session state mid-flight, not for initial population.

### AP-4: Treating `preferred_username` differences as different people

Any OIDC flow that compares usernames to decide "same user?" is wrong in both
directions (renames split one person in two; recycling merges two people into
one). Identity comparison is `oid` (or `(tid, oid)`) — always.

## Regeneration semantics

On password change, every session for the user is destroyed and the caller
gets a regenerated session. Custom session data is **resolved fresh** by the
configured resolver — which receives `Reason: ReasonRegeneration` so apps can
distinguish the trigger; values previously set via `UpdateCustomSessionData` do
not carry over, and if no resolver is configured the new session has no
custom-data row (decoders must tolerate all-NULL — see the LEFT JOIN
contract). This is correct for session data by definition; if it hurts,
see AP-2.

## Open questions

- **OQ-1:** ~~Should the library ever offer an optional, library-managed user
  table for OIDC?~~ **Resolved — implemented:** the OIDC user anchor
  (`WithOIDCUsers()`): an opt-in `OIDCUsers` table keyed per the "OIDC key
  choice" section (surrogate UUID PK, unique `(Tid, Oid)`), maintained
  just-in-time inside every login transaction, with `Username` as a mutable
  attribute. Custom user data attaches to it (FK → `OIDCUsers.Id`) with a
  claims-fed login hook. See the "OIDC user anchor" and "Custom user data"
  sections of the README.
- **OQ-2:** ~~Should the resolver be regeneration-aware?~~ **Resolved —
  implemented:** the resolver receives `NewSessionRequest.Reason`
  (`Login` / `ExternalAuth` / `Regeneration` / `Preauth`); default behavior is
  reset/re-resolve with no per-app code. Passing the prior session's custom
  data was deferred — adding a field to the request struct later is additive
  and non-breaking.
- **OQ-3:** ~~Preauth has no custom session data support.~~ **Resolved —
  implemented:** all three session types share the mechanism. Password auth:
  resolver + per-call data on `StartAuthenticatedSession`; OIDC: resolver fed
  raw verified claims; Preauth: caller-supplied per-call data on
  `Preauth.API().Login()`, atomic with the insert.
- **OQ-4:** ~~`StartAuthenticatedSession` vs `Preauth.Login` — do we need
  both?~~ **Resolved — keep both; boundary documented in godoc:**
  `StartAuthenticatedSession` requires an existing, non-disabled
  `SessionUsers` record and participates fully in custom session data
  (`ReasonExternalAuth`); `Preauth.Login` is trust-the-caller with no user
  record — the stepping-stone (e.g., MFA-pending) session. Each godoc names
  the other as the alternative.
- **OQ-5:** ~~Multi-tenant OIDC: do we take a position on `(tid, oid)`
  composite keys?~~ **Resolved:** the guidance takes a position — see
  "OIDC key choice" under P-1.
