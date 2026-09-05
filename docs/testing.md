# Testing this library

The suite is layered. Each layer answers a different question, and a change is usually
proven at more than one of them. Pick the layer by what could go wrong, not by where the
code lives.

## The layers

**Seam suite** (`internal/e2e`). Runs the library the way an application does: a public
session type mounted on a chi router, real cookies over an HTTPS test server, and the
public PostgreSQL storage on the shipped migrations. One scenario per security invariant.
Add a scenario when a property only holds if several layers agree, such as "the old cookie
is dead after the end". Needs Docker.

**Public surface** (`surface_test.go` in the root package). One scenario table runs
against all four session types, built through their constructors, with real cookies and a
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

**Verifiers** (`internal/azureoidc`, `internal/googleoidc`). Real login round trips
against `internal/oidctest.FakeIDP`, which signs real RS256 tokens. Both build tags are
tested: the production verifier under the default tag and the `skipAuth` simulator under
its own.

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
go test -run TestImpersonation ./sessionstorage/internal/...   # driver conformance
```

CI runs the suite with the race detector under the default, `skipAuth`, `insecurecookie`
and `skipAuth,insecurecookie` tags, and writes a per-package coverage table to the job
summary.
