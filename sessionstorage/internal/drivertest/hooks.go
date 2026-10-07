package drivertest

import (
	"context"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
)

// The application's hooks run inside the sign-in's transactions, and an application
// relies on what they write and read there. These cases pin that down: a refused or
// held sign-in keeps the hooks' own writes, and the policy and the custom session data
// resolver see the account a sign-in provisioned, and how it was resolved, on every
// backend.

// assertRecorded fails unless the hooks' write key=want was committed.
func assertRecorded(ctx context.Context, t *testing.T, h *AccountsHarness, raw any, key, want string) {
	t.Helper()

	got, found := h.Recorded(ctx, t, raw, key)
	if !found || got != want {
		t.Errorf("HookRecords[%q] = %q (found %v), want %q committed", key, got, found, want)
	}
}

func testRejectionKeepsResolverWrites(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, AccountsWithAppTables, AccountsConfig{Identities: true, Resolve: func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
		if err := tx.Record(ctx, "attempt:"+req.Identity.Subject, "refused: no invite"); err != nil {
			return nil, err
		}

		return &dbtype.Resolution{Outcome: dbtype.RejectIdentity, Refusal: "not_invited"}, nil
	}})

	_, _, err := signIn(ctx, in.Driver, lakeside("idp_stranger"), sessioninfo.ReasonLogin)

	assertRefused(t, err, "not_invited", dbtype.ErrIdentityRejected)
	assertRecorded(ctx, t, h, in.Raw, "attempt:idp_stranger", "refused: no invite")
	assertNoLink(ctx, t, in.Driver, lakeside("idp_stranger"))
}

func testHeldOrRefusedKeepsHookWrites(_ context.Context, t *testing.T, h *AccountsHarness) {
	tests := []struct {
		name     string
		password bool
		decision *dbtype.SignInDecision
		check    func(t *testing.T, err error)
	}{
		{
			name:     "a denied external sign-in",
			decision: &dbtype.SignInDecision{Outcome: dbtype.DenySignIn, Refusal: "sso_required"},
			check: func(t *testing.T, err error) {
				t.Helper()
				assertRefused(t, err, "sso_required", dbtype.ErrSignInDenied)
			},
		},
		{
			name:     "a denied password sign-in",
			password: true,
			decision: &dbtype.SignInDecision{Outcome: dbtype.DenySignIn, Refusal: "sso_required"},
			check: func(t *testing.T, err error) {
				t.Helper()
				assertRefused(t, err, "sso_required", dbtype.ErrSignInDenied)
			},
		},
		{
			name:     "a sign-in held for MFA",
			decision: &dbtype.SignInDecision{Outcome: dbtype.RequireMFA},
			check: func(t *testing.T, err error) {
				t.Helper()
				var pending *dbtype.PendingSignInError
				if !errors.As(err, &pending) {
					t.Errorf("sign-in error = %v, want a PendingSignInError", err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			in := h.New(ctx, t, AccountsWithAppTables, AccountsConfig{Identities: true, Policy: func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*dbtype.SignInDecision, error) {
				if err := tx.Record(ctx, "audit:"+req.UserID.String(), "decided"); err != nil {
					return nil, err
				}

				return tt.decision, nil
			}})
			user := passwordUser(ctx, t, in.Driver, "jane@lakeside.edu")

			var err error
			if tt.password {
				_, err = in.Driver.InsertSession(ctx, newInsertSession(user.Username), &sessioninfo.NewSessionRequest{
					Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID,
					Identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String()},
				})
			} else {
				mustLink(ctx, t, in.Driver, user.ID, lakeside("idp_jane"))
				_, _, err = signIn(ctx, in.Driver, lakeside("idp_jane"), sessioninfo.ReasonLogin)
			}

			tt.check(t, err)
			assertRecorded(ctx, t, h, in.Raw, "audit:"+user.ID.String(), "decided")
		})
	}
}

// provisioningResolver provisions username for every unlinked identity, with tenant,
// and records the application's membership row for the new account in OnProvisioned.
func provisioningResolver(username, tenant string) func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
	return func(ctx context.Context, tx HookTx, _ *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
		return &dbtype.Resolution{
			Outcome: dbtype.ProvisionAccount, NewUser: &dbtype.InsertSessionUser{Username: username}, Tenant: tenant,
			OnProvisioned: func(ctx context.Context, userID ccc.UUID) error {
				return tx.Record(ctx, "member:"+userID.String(), tenant)
			},
		}, nil
	}
}

// seesProvisioned reports why req's account is not visible as a provisioned account
// with its application rows in tx, or "" when it is.
func seesProvisioned(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest, tenant string) (string, error) {
	exists, err := tx.UserExists(ctx, req.UserID)
	if err != nil {
		return "", err
	}
	if !exists {
		return "the provisioned account is not readable", nil
	}
	member, found, err := tx.Recorded(ctx, "member:"+req.UserID.String())
	if err != nil {
		return "", err
	}
	if !found || member != tenant {
		return "the rows OnProvisioned wrote are not readable", nil
	}
	if !req.Account.Provisioned() || req.Account.ID != req.UserID || req.Account.Tenant != tenant {
		return "the request does not say the account was provisioned", nil
	}

	return "", nil
}

func testPolicySeesProvisionedAccount(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, AccountsWithAppTables, AccountsConfig{
		Identities: true,
		Resolve:    provisioningResolver("new@lakeside.edu", "partner-1"),
		Policy: func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*dbtype.SignInDecision, error) {
			unseen, err := seesProvisioned(ctx, tx, req, "partner-1")
			if err != nil || unseen != "" {
				return &dbtype.SignInDecision{Outcome: dbtype.DenySignIn, Refusal: sessioninfo.LoginRefusalCode(unseen)}, err
			}

			return &dbtype.SignInDecision{Outcome: dbtype.AllowSignIn}, nil
		},
	})

	id, req, err := signIn(ctx, in.Driver, lakeside("idp_new"), sessioninfo.ReasonLogin)
	if err != nil {
		t.Fatalf("first sign-in error = %v (code %q), want the policy to see the provisioned account and allow", err, sessioninfo.LoginRefusalCodeOf(err))
	}
	if sess := mustSession(ctx, t, in.Driver, id); sess.UserID != ccc.NullUUIDFromUUID(req.UserID) {
		t.Errorf("Session().UserID = %v, want the provisioned account %v", sess.UserID, req.UserID)
	}
}

func testCustomDataSeesProvisionedAccount(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, AccountsWithAppTables, AccountsConfig{
		Identities: true,
		Resolve:    provisioningResolver("new@lakeside.edu", "partner-1"),
		CustomData: func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (any, error) {
			unseen, err := seesProvisioned(ctx, tx, req, "partner-1")
			if err != nil {
				return nil, err
			}
			if unseen != "" {
				return nil, errors.New(unseen)
			}

			return &CustomStringData{CustomString: "member of partner-1"}, nil
		},
	})

	id, _, err := signIn(ctx, in.Driver, lakeside("idp_new"), sessioninfo.ReasonLogin)
	if err != nil {
		t.Fatalf("first sign-in error = %v, want the custom session data resolver to see the provisioned account", err)
	}
	data, ok := mustSession(ctx, t, in.Driver, id).CustomData.(*CustomStringData)
	if !ok || data.CustomString != "member of partner-1" {
		t.Errorf("Session().CustomData = %#v, want the resolver's data", data)
	}
}

func testPendingRowSkipsCustomData(ctx context.Context, t *testing.T, h *AccountsHarness) {
	var calls int
	in := h.New(ctx, t, AccountsWithAppTables, AccountsConfig{
		Identities: true,
		CustomData: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (any, error) {
			calls++

			return nil, errors.New("a resolver that looks the account up fails without one")
		},
	})

	id, err := in.Driver.InsertSession(ctx, newInsertSession("pat@lakeside.edu"), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonPendingIdentity, Username: "pat@lakeside.edu"})
	if err != nil {
		t.Fatalf("InsertSession() of a pending identity's row error = %v, want it inserted without the resolver", err)
	}
	if calls != 0 {
		t.Errorf("custom session data resolver ran %d times for a pending identity's row, want 0", calls)
	}
	sess := mustSession(ctx, t, in.Driver, id)
	if sess.UserID.Valid || sess.AuthenticatedAt != nil {
		t.Errorf("pending row = UserID %v, AuthenticatedAt %v; want no account and never authenticated", sess.UserID, sess.AuthenticatedAt)
	}
}

func testSignInAccountReported(_ context.Context, t *testing.T, h *AccountsHarness) {
	tests := []struct {
		name string
		// signIn runs the sign-in for the seeded accounts and returns its request.
		signIn func(ctx context.Context, t *testing.T, d AccountsDriver, sso, pat *dbtype.SessionUser) (*sessioninfo.NewSessionRequest, error)
		want   func(sso, pat *dbtype.SessionUser, req *sessioninfo.NewSessionRequest) *sessioninfo.SignInAccount
	}{
		{
			name: "an existing link, with its tenant",
			signIn: func(ctx context.Context, t *testing.T, d AccountsDriver, sso, _ *dbtype.SessionUser) (*sessioninfo.NewSessionRequest, error) {
				t.Helper()
				if _, err := d.LinkIdentity(ctx, sso.ID, lakeside("idp_sso"), "partner-1"); err != nil {
					t.Fatalf("LinkIdentity() error = %v", err)
				}
				_, req, err := signIn(ctx, d, lakeside("idp_sso"), sessioninfo.ReasonLogin)

				return req, err
			},
			want: func(sso, _ *dbtype.SessionUser, _ *sessioninfo.NewSessionRequest) *sessioninfo.SignInAccount {
				return &sessioninfo.SignInAccount{ID: sso.ID, Username: sso.Username, Source: sessioninfo.AccountExistingLink, Tenant: "partner-1"}
			},
		},
		{
			name: "a link the resolver made",
			signIn: func(ctx context.Context, _ *testing.T, d AccountsDriver, _, _ *dbtype.SessionUser) (*sessioninfo.NewSessionRequest, error) {
				_, req, err := signIn(ctx, d, lakeside("idp_link"), sessioninfo.ReasonLogin)

				return req, err
			},
			want: func(sso, _ *dbtype.SessionUser, _ *sessioninfo.NewSessionRequest) *sessioninfo.SignInAccount {
				return &sessioninfo.SignInAccount{ID: sso.ID, Username: sso.Username, Source: sessioninfo.AccountNewLink, Tenant: "partner-2"}
			},
		},
		{
			name: "an account the resolver provisioned",
			signIn: func(ctx context.Context, _ *testing.T, d AccountsDriver, _, _ *dbtype.SessionUser) (*sessioninfo.NewSessionRequest, error) {
				_, req, err := signIn(ctx, d, lakeside("idp_new"), sessioninfo.ReasonLogin)

				return req, err
			},
			want: func(_, _ *dbtype.SessionUser, req *sessioninfo.NewSessionRequest) *sessioninfo.SignInAccount {
				return &sessioninfo.SignInAccount{ID: req.UserID, Username: "new@lakeside.edu", Source: sessioninfo.AccountProvisioned, Tenant: "partner-3"}
			},
		},
		{
			name: "a password sign-in's named account",
			signIn: func(ctx context.Context, _ *testing.T, d AccountsDriver, _, pat *dbtype.SessionUser) (*sessioninfo.NewSessionRequest, error) {
				req := &sessioninfo.NewSessionRequest{
					Reason: sessioninfo.ReasonLogin, Username: pat.Username, UserID: pat.ID,
					Identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: pat.ID.String()},
				}
				_, err := d.InsertSession(ctx, newInsertSession(pat.Username), req)

				return req, err
			},
			want: func(_, pat *dbtype.SessionUser, _ *sessioninfo.NewSessionRequest) *sessioninfo.SignInAccount {
				return &sessioninfo.SignInAccount{ID: pat.ID, Username: pat.Username, HasPassword: true, Source: sessioninfo.AccountNamed}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			var sso *dbtype.SessionUser
			in := h.New(ctx, t, Accounts, AccountsConfig{Identities: true, Resolve: func(_ context.Context, _ HookTx, req *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
				if req.Identity.Subject == "idp_link" {
					return &dbtype.Resolution{Outcome: dbtype.LinkIdentity, UserID: sso.ID, Tenant: "partner-2"}, nil
				}

				return &dbtype.Resolution{Outcome: dbtype.ProvisionAccount, NewUser: &dbtype.InsertSessionUser{Username: "new@lakeside.edu"}, Tenant: "partner-3"}, nil
			}})
			sso = createUser(ctx, t, in.Driver, "sso@lakeside.edu")
			pat := passwordUser(ctx, t, in.Driver, "pat@lakeside.edu")

			req, err := tt.signIn(ctx, t, in.Driver, sso, pat)
			if err != nil {
				t.Fatalf("sign-in error = %v", err)
			}
			if diff := cmp.Diff(tt.want(sso, pat, req), req.Account); diff != "" {
				t.Errorf("NewSessionRequest.Account mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
