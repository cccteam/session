# Testing this library

The suite is layered. Each layer answers a different question, and a change is usually
proven at more than one of them. Pick the layer by what could go wrong, not by where the
code lives.

## The layers

**Seam suite** (`internal/e2e`). Runs the library the way an application does: a public
session type mounted on a chi router, real cookies over an HTTPS test server, and the
public PostgreSQL storage on the shipped migrations. One scenario per security invariant.
Add a scenario when a property only holds if several layers agree, such as "the old cookie
is dead after the end". The Auth scenarios run password and WorkOS sign-in on one `Auth`
against a fake WorkOS code exchange (`TestAuthSeams_PasswordAndWorkOS`), and Azure and
Google sign-in against `oidctest.FakeIDP` (`TestAuthSeams_AzureAndGoogle`, production
verifiers only, so not under `skipAuth`). Their account resolver and sign-in policy can
take the transaction (`hooks.resolveTx`, `hooks.policyTx`) to write and read the
application's own tables (`PartnerMembers`, `SignInAttempts`, created over the shipped
schema), which is how the scenarios prove a hook's write survives a refusal and a policy
reads the account a sign-in provisioned. Needs Docker.

**Public surface** (`surface_test.go` in the root package). One scenario table runs
against all five session types (including `Auth`), built through their constructors, with real cookies and a
mocked store. It exists because the types satisfy `basesession.Handlers` through
delegates, and a delegate forwarded to the wrong base method compiles. Add a scenario
whenever a handler or middleware is added to the shared interface.

**Engine** (`internal/basesession`). The shared middleware and the impersonation
lifecycle against mocked store and cookies. This is where a rule is exercised in its
branches: every refusal, every ordering, every failure mode.

**Storage contract** (`sessionstorage`). The public store over a generated mock of the
driver interface. Proves the mapping between public and driver types and that errors
propagate.

**Driver conformance** (`sessionstorage/internal/drivertest`). One case table, run by
both driver packages through a small `Harness`. A case added here runs against PostgreSQL
and Spanner containers; a case that passes on one backend and fails on the other is the
divergence the suite exists to catch. Driver behaviour that is not impersonation still
lives in each driver's own `*_test.go`, which is where new conformance tables should be
carved from next. Needs Docker.

The accounts cases (`RunAccounts`) give the application's hooks a `HookTx`, which each
harness adapts to its backend's transaction, so a case can have the resolver, the policy
and the custom session data resolver write and read rows as an application does. Those
cases prepare the `AccountsWithAppTables` schema: the shipped accounts migrations plus
the driver package's `testdata/accounts_test/app_tables` fixture (`HookRecords` and a
`SessionCustomData` table). This is where a difference in transaction visibility between
the backends shows up: Spanner's buffered writes are invisible to later reads in the same
transaction, PostgreSQL's are not.

**Verifiers** (`internal/azureoidc`, `internal/googleoidc`, `internal/workossso`). Real
login round trips against `internal/oidctest.FakeIDP`, which signs real RS256 tokens, and,
for WorkOS, against a fake code exchange. Both build tags are
tested: the production verifier under the default tag and the `skipAuth` simulator under
its own. The Google groups lookup has the same split: `googlegroups` is the Admin SDK
adapter under the default tag and, under `skipAuth`, the simulated directory that answers
groups from `APP_ROLES`; `role_sync_google_skipAuth_test.go` proves the role sync reads
those simulated groups as exactly the roles `APP_ROLES` names, so a directory-run Google
auth can be signed in to in development.

## Conventions

- **Case table and a shared runner.** No chains of ad hoc `t.Run` calls. Name cases as
  the sentence a reviewer would say: what is done and what must be true.
- **Assert the error class, not just its presence.** A security test that only checks
  `err != nil` cannot tell a refusal from a server error. Use `httpio.HasForbidden`,
  `HasUnauthorized`, `HasBadRequest`, or `errors.Is` against a sentinel. `wantErr bool`
  alone is for plumbing tests.
- **Assert the effect a caller observes.** A status code, a body, a cookie on the
  response, a row in the database, an event delivered to the hook. A mock expectation
  proves a call was made, which is weaker.
- **Fixtures come from the shipped schema.** Container tests apply the migrations under
  `schema/`. A fixture directory holds only what the shipped schema does not: seeded rows
  and test-only tables.
- **Shared helpers live in importable packages.** `internal/testkey` holds the cookie
  master key every suite uses; `internal/oidctest` the fake identity provider and cookie
  client; `sessionstorage/internal/drivertest` the driver cases. These are ordinary
  packages so tests in any package can import them; the linter grants them the same
  allowances as `_test.go` files.
- **Prove a new test can fail.** Before committing a regression test, break the code it
  guards and watch it fail, then restore. A test that passes on the bug is worse than
  none, because it is trusted.
- **Update the invariant matrix.** `docs/security-invariants.md` names each property and
  the test that proves it. A change to sessions, cookies or impersonation updates the row
  it affects.

## Running

```sh
go test ./...                                   # everything, needs Docker for the containers
go test -tags skipAuth ./...                    # the development authenticator
go test -tags insecurecookie ./...              # the development cookie configuration
go test -run TestSeams ./internal/e2e           # the seam suite alone
go test -run TestAuthSeams ./internal/e2e       # the Auth seam scenarios
go test -run TestImpersonation ./sessionstorage/internal/...   # driver conformance
go test -run TestAccounts ./sessionstorage/internal/...        # accounts, identities and auth events conformance
```

CI runs the suite with the race detector under the default, `skipAuth`, `insecurecookie`
and `skipAuth,insecurecookie` tags, and writes a per-package coverage table to the job
summary.
