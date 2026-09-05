# Security invariants and where each is proven

This is the list of properties the session library must hold, with the test that proves
each one. A pull request that touches sessions, cookies or impersonation updates the row
it affects. "Layer" says where the proof lives; a property is only *proven* when a test
asserts the property itself, not merely that a call was made.

Layers, from the outside in:

| Layer | Package | What is real | Runs where |
| --- | --- | --- | --- |
| Seam suite | `internal/e2e` | A public session type on a chi router, real cookies over HTTPS, the public PostgreSQL storage on the shipped migrations | Docker |
| Public surface | root `session` (`surface_test.go`) | Every handler and middleware on all four types, real cookies, mocked store | anywhere |
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
| O5 | The simulated (`skipAuth`) login fabricates exactly the claims the real one would carry | `*_skipAuth_test.go` in both packages | verifier |

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
