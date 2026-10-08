# Security invariants and where each is proven

This is the list of properties the session library must hold, with the test that proves
each one. A pull request that touches sessions, cookies or impersonation updates the row
it affects. "Layer" says where the proof lives; a property is only *proven* when a test
asserts the property itself, not merely that a call was made.

Layers, from the outside in:

| Layer | Package | What is real | Runs where |
| --- | --- | --- | --- |
| Seam suite | `internal/e2e` | A public session type on a chi router, real cookies over HTTPS, the public PostgreSQL storage on the shipped migrations | Docker |
| Public surface | root `session` (`surface_test.go`) | Every handler and middleware on all five types, real cookies, mocked store | anywhere |
| Engine | `internal/basesession` | The shared middleware and impersonation lifecycle, mocked store and cookies | anywhere |
| Storage contract | `sessionstorage` | The public store over a generated mock of the driver | anywhere |
| Driver conformance | `sessionstorage/internal/drivertest`, run by both drivers | Real PostgreSQL and Spanner containers, one case table | Docker |

## Sessions and cookies

| # | Invariant | Proven by | Layer |
| --- | --- | --- | --- |
| S1 | A request without a valid auth cookie starts a new, unauthenticated session and never inherits one | `TestSessionTypes_PublicSurface/*/StartSession…` | public surface |
| S2 | An expired or idle session is refused with 401 and its handler never runs | `TestBaseSession_ValidateSessionAPI_*`; `TestSeams/logout…`, `…hard cap…` | engine, seam |
| S3 | A non-safe request without the session's XSRF token in both cookie and header is refused with 403 | `TestSessionTypes_PublicSurface/*/ValidateXSRFToken…`; `internal/cookie` `Test_validate_*` | public surface, cookie |
| S4 | An XSRF token minted for one session is refused on another | `TestSeams/the actor's XSRF token…` | seam |
| S5 | Logout expires the row so the cookie cannot be replayed | `TestSeams/logout…`; driver `DestroySession` cases | seam, driver |
| S6 | The post-login return URL cannot redirect off-site | `internal/cookie` `Test_SanitizeReturnURL`; `googleoidc_skipAuth_test.go/…sanitized…` | cookie, verifier |

## OIDC login

| # | Invariant | Proven by | Layer |
| --- | --- | --- | --- |
| O1 | The callback is bound to the login this browser started: state must match the OIDC cookie | `internal/azureoidc` and `internal/googleoidc` `TestOIDC_Verify/state mismatch` | verifier |
| O2 | A token for another client or from another issuer is rejected | `TestOIDC_Verify/…audience…`, `…issuer…` | verifier |
| O3 | PKCE verifier and state are fresh per login | `TestOIDC_AuthCodeURL` in both packages | verifier |
| O4 | Google logins outside the hosted domain, or with an unverified email, are refused | `internal/googleoidc` `TestOIDC_Verify/hd…`, `…unverified…` | verifier |
| O5 | The simulated (`skipAuth`) login fabricates exactly the claims the real one would carry, and the simulated Google groups lookup yields exactly the roles `APP_ROLES` names | `*_skipAuth_test.go` in both packages; `role_sync_google_skipAuth_test.go` | verifier |
| O6 | Each OIDC provider keeps its own state cookie (`OIDC-azure`, `OIDC-google`, `OIDC-workos`), so logins with different providers in one browser never overwrite each other's state; a login started before the upgrade completes with the legacy shared `OIDC` cookie, which is then cleared | `internal/googleoidc` `TestOIDC_StateCookie_ProvidersCoexist`; `TestOIDC_Verify_LegacyStateCookie` in both packages | verifier |

## Accounts and sign-in

| # | Invariant | Proven by | Layer |
| --- | --- | --- | --- |
| A1 | A password-less account (no `PasswordHash`) fails every password check as invalid credentials: ValidateCredentials and Login refuse with 401 and start no session, change-password refuses the old password and keeps the account's sessions; the hasher never sees a nil hash; such an account is stored and read with no hash on both backends | `TestPasswordAuth_PasswordLessAccount`; `TestPasswordAuth_Login_PasswordLessAccount`; `TestSessionStorageDriver_PasswordLessAccount` (spanner, postgres) | root, driver |
| A2 | An external identity whose key is longer than a GUID (a WorkOS `idp_id`) is anchored whole on both backends' shipped OIDC schema; Spanner `OIDCUsers.Tid`/`Oid` are `STRING(MAX)` | `TestSessionStorageDriver_OIDCUsers_LongKey` (spanner, postgres) | driver |
| A3 | The accounts schema is opt-in: a driver without it never names `Sessions.UserId`, `AuthenticatedAt` or the auth events table, so a legacy schema keeps working | drivertest `TestAccounts/a legacy schema keeps working…` | driver |
| A4 | A session records the account it belongs to and when it was authenticated; a preauth stepping stone and a pending identity's row have neither, and a role-principal impersonation has no account | drivertest `TestAccounts/account sessions record…`, `…impersonated session records its account…` | driver |
| A5 | A session's auth events are written with it, read with it oldest first, and deleted with it; an impersonated session's event names the actor | drivertest `TestAccounts/the first auth event…`, `…impersonated session records…`, `…auth events go with it`; `sessionstorage` `TestSessionStorage_Session_Account` | driver, storage contract |
| A6 | An external identity is keyed by (Method, Connection, Subject), never by email: a linked identity signs in to its account without consulting the account resolver, and the session carries that account's ID and username | drivertest `TestAccounts/a linked identity signs in…` | driver |
| A7 | The library never links on its own: an unlinked identity is linked or provisioned only on the resolver's outcome, and LinkIdentity to an account that has a password is refused (`ErrLinkRequiresConfirmation`) unless the resolution is TrustedForLinking | drivertest `TestAccounts/the resolver's outcome decides…` | driver |
| A8 | A refused or pending sign-in starts no session and keeps the hooks' own writes: RejectIdentity, RequireConfirmation, DenySignIn and RequireMFA commit what the resolver and the policy wrote, and the account resolution (an account the resolver provisioned, and its link, stay when the policy denies or holds the sign-in; an MFA wait names that account). Only an error rolls back: an OnProvisioned failure leaves no account and no link. Refusals carry their code and cause, pending outcomes a `PendingSignInError` | drivertest `TestAccounts/a rejected sign-in keeps the account resolver's own writes`, `…a denied or held sign-in keeps the sign-in policy's own writes`, `…the resolver's outcome decides…`, `…the sign-in policy decides…`; `TestAuthSeams_PasswordAndWorkOS/a WorkOS sign-in the resolver rejects keeps…` | driver, seam |
| A9 | The sign-in policy decides every sign-in method (external and password) once the account is known and before any session exists; a step-up completion is not decided again. The account resolution has committed when it runs, so it reads an account the sign-in provisioned and the rows OnProvisioned wrote on both backends, and `NewSessionRequest.Account` says how the account was found | drivertest `TestAccounts/the sign-in policy decides…`, `…the policy of a provisioning sign-in reads…`, `…a sign-in reports the account it resolved to and how`; `TestAuthSeams_PasswordAndWorkOS/a first WorkOS sign-in provisions the account, and a policy that reads…` | driver, seam |
| A10 | A sign-in to a disabled account is refused (`account_disabled`) | drivertest `TestAccounts/a disabled account is refused` | driver |
| A11 | Concurrent first sign-ins of one identity link it exactly once and all succeed | drivertest `TestAccounts/concurrent first sign-ins…` | driver |
| A12 | The last means of sign-in of a password-less account can't be unlinked (`ErrLastSignInMethod`, Conflict); an identity can't be linked twice | drivertest `TestAccounts/links are managed outside sign-in…` | driver |
| A13 | Revoking an account's sessions works by UserId: its own sessions under any username, user-principal impersonations of it, and sessions it holds as a local actor end (records Revoked); another account's session under the same username survives | drivertest `TestAccounts/DestroyUserSessions…` | driver |
| A14 | An external identity is never signed in without an identities configuration (`ErrIdentitiesNotConfigured`) | drivertest `TestAccounts/an external identity needs…`; `sessionstorage` `TestAccounts_IdentitiesEnabled` | driver, storage contract |
| A15 | A session insert records every auth event it carries, in order, in the same write as the session row; one without events records its sign-in method | drivertest `TestAccounts/a session insert records every auth event…`, `…the first auth event…` | driver |
| A16 | Deleting an account deletes its identity links in the same transaction, so no link outlives its account | drivertest `TestAccounts/deleting an account deletes its identity links…` | driver |
| A17 | An Auth sign-in's custom session data is written with its session row, by a resolver that runs after the account resolution committed (it reads a provisioned account and knows how the account was found); the resolver never runs for a pending identity's row, which carries no custom data | drivertest `TestAccounts/the custom session data resolver of a provisioning sign-in…`, `…a pending identity's row never calls…`; `TestAuth_PendingStatusAndCancel` (the row's `ReasonPendingIdentity`) | driver, root |

## Auth sessions

| # | Invariant | Proven by | Layer |
| --- | --- | --- | --- |
| U1 | An external method can't be registered on storage without identities: its registration panics with an error wrapping `ErrIdentitiesNotConfigured`, the message naming the method; a misconfigured method (no role sync slot, no hosted domain, a cookie option given to `PasswordSignIn`) is refused at registration, and the Auth's own options at construction | `TestAuth_RegistrationRefused/the … method on storage without identities`, `…a cookie option given to the password method…`, `…an Azure method without its role sync slot`, `…a Google method without its hosted domain`; `TestNewAuth` | root |
| U2 | Every sign-in, confirmation and MFA completion issues a new session ID, and its cookies are written only after the session row, its auth events and role synchronization succeeded: a refusal writes no session cookie | `TestAuth_PasswordLogin`; `TestAuth_AzureCallback/role sync that leaves no recognized role…`; `TestAuthAPI_CompletePending`; `TestAuthSeams_PasswordAndWorkOS/a password sign-in establishes a session under a new ID…`, `…the application's MFA step completes it under a new session ID` | root, seam |
| U3 | A sign-in that waits (confirmation or MFA) starts no session; a pending identity's row belongs to no account, never validates, and is inserted with `ReasonPendingIdentity` | `TestAuth_ValidateSession/a session that belongs to no account…`; `TestAuthSeams_PasswordAndWorkOS/…waits for that password…`, `…requires MFA holds the password sign-in…` | root, seam |
| U4 | A pending identity is single-use and unforgeable: completing, cancelling or replacing it expires its row, a copy of its cookie then answers `pending_expired`, and a cookie the key did not seal is ignored | `TestAuth_PendingConfirmWithPassword/a pending identity whose row is no longer live…`; `TestAuth_PendingStatusAndCancel`; `TestAuthSeams_PasswordAndWorkOS/…waits for that password…`, `…requires MFA…` | root, seam |
| U5 | A link confirmation requires the existing account's password: a wrong one links nothing and leaves the pending identity; an identity linked meanwhile to another account is refused | `TestAuth_PendingConfirmWithPassword`; `TestAuthSeams_PasswordAndWorkOS/…waits for that password…` | root, seam |
| U6 | An MFA completion is not decided by the policy again, and must resolve to the account it waited on | `TestAuthAPI_CompletePending`; `TestAuthSeams_PasswordAndWorkOS/a confirmed link the policy still holds for MFA…` | root, seam |
| U7 | `ValidateSession` loads the session's account by `UserId` on every request and refuses a session whose account is missing or disabled | `TestAuth_ValidateSession`; `TestSessionTypes_PublicSurface/Auth/…`; `TestAuthSeams_PasswordAndWorkOS/a disabled account's session is refused…` | root, public surface, seam |
| U8 | A sign-in's return path never leaves the application: a login whose `returnUrl` is absolute, `//host` or `/\host` is refused with 400, and the callback sanitizes it again | `TestAuth_ExternalLogin`; `internal/workossso` `TestClient_Verify/…off-site return URL…`; `TestAuthSeams_PasswordAndWorkOS/the WorkOS login refuses a returnUrl…` | root, verifier, seam |
| U9 | A WorkOS callback is bound to the login this browser started: its `OIDC-workos` state cookie must be present and match, and is single-use; the code exchange authenticates with the API key in a JSON body | `internal/workossso` `TestClient_Verify`, `TestClient_AuthorizationURL`; `TestAuthSeams_PasswordAndWorkOS/a WorkOS callback that does not match…` | verifier, seam |
| U10 | Refusals reach the page as codes only: `?code=` on a redirect, `{"code"}` in JSON; a pending sign-in as `?pending=<reason>`, or the URL the application's PendingHook chose | `TestAuth_AzureCallback`; `TestAuth_PasswordLogin`; `TestPendingRedirectURL`; `TestAuthSeams_PasswordAndWorkOS/a refused WorkOS sign-in…` | root, seam |
| U11 | External identities reach their accounts by (method, connection, subject), never by email: the same subject in another connection is another identity | `TestAuthSeams_AzureAndGoogle/Azure and Google identities reach one account…`; `TestAuth_GoogleCallback` | seam, root |
| U12 | Every identity link is reported to the `IdentityLinked` hook (a confirmation's and the resolver's) once, from the storage's own account resolution, whatever the sign-in's outcome (a provisioning sign-in denied or held for MFA has committed its link); a sign-in through an existing link reports nothing; the hook's failure does not undo the link | `TestAuth_IdentityLinkedHook`; `TestAuth_PendingConfirmWithPassword`; `TestAuthSeams_PasswordAndWorkOS/a first WorkOS sign-in provisions…`, `…a provisioning sign-in held for MFA…` | root, seam |
| U13 | Role synchronization reconciles the roles of the account the identity resolved to, never before an unconfirmed identity is linked | `TestAuth_AzureCallback` | root |
| U14 | A user-principal impersonation belongs to the impersonated account and a role principal's to none; the session's event names the actor | `TestAuthAPI_StartImpersonatedSession`; `TestAuthSeams_PasswordAndWorkOS/…a user-principal impersonation belongs to the impersonated account` | root, seam |
| U15 | The `PendingHook` runs only after the pending identity is stored and its cookie set, receives the account it waits on (a provisioned one included), and changes nothing about it; its URL or its own response replaces the default redirect, and its error discards the pending identity (row expired, cookie deleted) and fails the sign-in | `TestAuth_PendingHook`; `TestAuthSeams_PasswordAndWorkOS/a provisioning sign-in held for MFA names the new account to the pending hook…` | root, seam |
| U16 | The handler is the proof of registration: a route can only be wired from the value a method's registration returned, so a method that was not registered has no handler to wire; each method is its own type with only its own handlers (`FrontChannelLogout` only on `*AzureMethod`, `ChangeUserPassword` only on `*PasswordMethod`) | `auth_methods_test.go` (compile-time assertions), `TestSignInMethodTypes_HandlerSets`; `TestAuth_RegisterSignInMethods`; every flow test (`TestAuth_ExternalLogin`, `TestAuth_AzureCallback`, `TestAuth_GoogleCallback`, `TestAuth_PasswordLogin`, the seam suites) wires its routes from registered values | root, seam |
| U17 | A sign-in method is registered at most once on an Auth: a second registration of the same method panics | `TestAuth_RegistrationRefused/the … method registered twice` | root |
| U18 | No sign-in method is registered once the Auth is in use (it has served a request through any of its handlers or middleware, or read its methods for a password check or hash through its API): the registration panics, and one racing the first request either lands before it or is refused, never half-seen by the request | `TestAuth_RegistrationRefused/a method registered after the Auth served its first request`, `…a first method registered after the Auth served a request`, `…after the Auth hashed a password through its API`; `TestAuth_RegistrationRacingTheFirstRequest` (under `-race`) | root |

## Impersonation

| # | Invariant | Proven by | Layer |
| --- | --- | --- | --- |
| I1 | An impersonated session cannot establish another (no chaining) | `TestSessionTypes_PublicSurface/*/StartImpersonatedSession refuses…`; `TestSeams/an impersonated session cannot impersonate` | public surface, seam |
| I2 | A request on a validated session can only impersonate as that session's user, from that session | `TestBaseSession_StartImpersonatedSession_LocalActor/on a validated session…` | engine |
| I3 | A local actor's source session must be live, theirs, and not itself impersonated | `TestBaseSession_StartImpersonatedSession_LocalActor` | engine |
| I4 | The actor is recoverable from every impersonated request and stamped on logs and spans | `sessioninfo` `ActorFromCtx` tests; `internal/basesession/tracing_test.go`; driver `Session reads the record…` | sessioninfo, engine, driver |
| I5 | The principal is the record's, never the actor's; a role impersonation skips the resolver | `sessioninfo` `PrincipalFromCtx` tests; `internal/basesession/principal_test.go` | sessioninfo, engine |
| I6 | A read-only session cannot reach any mutating handler | `TestSessionTypes_PublicSurface/*/EnforceReadOnlyMask…`; `TestSeams/a read-only impersonation…` | public surface, seam |
| I7 | Ending an impersonation expires the row and ends the record in one transaction; the old cookie is dead | `TestBaseSession_EndImpersonationAPI`; driver `DestroyImpersonatedSession…released…`; `TestSeams/a read-only impersonation…` | engine, driver, seam |
| I8 | A session whose record has ended never validates, whatever the row says | `TestBaseSession_ValidateSessionAPI_Impersonation/ended record on a live row…`; `TestSessionTypes_PublicSurface/*/ValidateSession refuses…` | engine, public surface |
| I9 | The hard cap refuses the next request and ends the record Expired | `TestBaseSession_ValidateSessionAPI_Impersonation`; `TestSeams/the hard cap…` | engine, seam |
| I10 | Destroying the actor's sessions revokes every impersonation they hold as a local actor | driver `DestroyImpersonatedSessions…`, `username-keyed operations…`; `TestSeams/destroying the actor's sessions…` | driver, seam |
| I11 | An operator's revocation refuses the next request and removes the session from the listing | `TestSeams/an operator revokes…` | seam |
| I12 | Every end is announced once as an Ended event on every type, including logout | `TestSessionAPIs_Logout_AnnouncesImpersonationEnd`; `TestSessionTypes_PublicSurface/*/Logout…`, `…EndImpersonation…` | public surface |
| I13 | A same-named role session and an account stay distinct; a foreign role session survives the account's username-keyed operations | driver `username-keyed operations…`; `TestPasswordAuthAPI_StartImpersonatedSession/a foreign actor's role principal is refused…` | driver, root |
| I14 | Both storage backends implement identical semantics | the shared `drivertest` suite runs unchanged on both | driver |

Not a library property, and therefore not tested here: *who may impersonate whom*, and who
may list or revoke. The library records what happened and binds the request to its
session; the application's guard decides. The seam suite's `/admin` routes are open to any
validated session for that reason.
