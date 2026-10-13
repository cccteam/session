package drivertest

import (
	"context"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
)

// The application's hooks run inside the sign-in's transactions. These cases check
// that a refused or held sign-in keeps the hooks' own writes, and that the policy and
// the custom session data resolver see a provisioned user and how it was resolved,
// on every backend.

// assertRecorded fails unless the hooks' write key=want was committed.
func assertRecorded(ctx context.Context, t *testing.T, h *AuthHarness, raw any, key, want string) {
	t.Helper()

	got, found := h.Recorded(ctx, t, raw, key)
	if !found || got != want {
		t.Errorf("HookRecords[%q] = %q (found %v), want %q committed", key, got, found, want)
	}
}

func testRejectionKeepsResolverWrites(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, AuthWithAppTables, AuthConfig{Auth: true, Resolve: func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		if err := tx.Record(ctx, "attempt:"+req.Identity.Subject, "refused: no invite"); err != nil {
			return nil, errors.Wrap(err, "HookTx.Record()")
		}

		return &signin.Resolution{Outcome: signin.RejectIdentity, Refusal: "not_invited"}, nil
	}})

	_, _, err := signIn(ctx, in, lakeside("idp_stranger"), sessioninfo.ReasonLogin)

	assertRefused(t, err, "not_invited", signin.ErrIdentityRejected)
	assertRecorded(ctx, t, h, in.Raw, "attempt:idp_stranger", "refused: no invite")
	assertNoLink(ctx, t, in.Driver, lakeside("idp_stranger"))
}

func testHeldOrRefusedKeepsHookWrites(_ context.Context, t *testing.T, h *AuthHarness) {
	tests := []struct {
		name     string
		password bool
		decision *signin.Decision
		check    func(t *testing.T, err error)
	}{
		{
			name:     "a denied external sign-in",
			decision: &signin.Decision{Outcome: signin.DenySignIn, Refusal: "sso_required"},
			check: func(t *testing.T, err error) {
				t.Helper()
				assertRefused(t, err, "sso_required", signin.ErrSignInDenied)
			},
		},
		{
			name:     "a denied password sign-in",
			password: true,
			decision: &signin.Decision{Outcome: signin.DenySignIn, Refusal: "sso_required"},
			check: func(t *testing.T, err error) {
				t.Helper()
				assertRefused(t, err, "sso_required", signin.ErrSignInDenied)
			},
		},
		{
			name:     "a sign-in held for MFA",
			decision: &signin.Decision{Outcome: signin.RequireMFA},
			check: func(t *testing.T, err error) {
				t.Helper()
				var pending *signin.PendingSignInError
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

			in := h.New(ctx, t, AuthWithAppTables, AuthConfig{Auth: true, Policy: func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*signin.Decision, error) {
				if err := tx.Record(ctx, "audit:"+req.UserID.String(), "decided"); err != nil {
					return nil, errors.Wrap(err, "HookTx.Record()")
				}

				return tt.decision, nil
			}})
			user := passwordUser(ctx, t, in.Driver, "jane@lakeside.edu")

			var err error
			if tt.password {
				_, err = passwordSignIn(ctx, in, user, sessioninfo.ReasonLogin)
			} else {
				mustLink(ctx, t, in.Driver, user.ID, lakeside("idp_jane"))
				_, _, err = signIn(ctx, in, lakeside("idp_jane"), sessioninfo.ReasonLogin)
			}

			tt.check(t, err)
			assertRecorded(ctx, t, h, in.Raw, "audit:"+user.ID.String(), "decided")
		})
	}
}

// provisioningResolver provisions username for every unlinked identity, with tenant,
// and records the application's membership row for the new user in OnProvisioned.
func provisioningResolver(username, tenant string) func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
	return func(_ context.Context, tx HookTx, _ *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		return &signin.Resolution{
			Outcome: signin.ProvisionUser, NewUser: &signin.NewUser{Username: username}, Tenant: tenant,
			OnProvisioned: func(ctx context.Context, userID ccc.UUID) error {
				return tx.Record(ctx, "member:"+userID.String(), tenant)
			},
		}, nil
	}
}

// seesProvisioned reports why req's user is not visible as a provisioned user
// with its application rows in tx, or "" when it is.
func seesProvisioned(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest, tenant string) (string, error) {
	exists, err := tx.UserExists(ctx, req.UserID)
	if err != nil {
		return "", errors.Wrap(err, "HookTx.UserExists()")
	}
	if !exists {
		return "the provisioned user is not readable", nil
	}
	member, found, err := tx.Recorded(ctx, "member:"+req.UserID.String())
	if err != nil {
		return "", errors.Wrap(err, "HookTx.Recorded()")
	}
	if !found || member != tenant {
		return "the rows OnProvisioned wrote are not readable", nil
	}
	if !req.User.Provisioned() || req.User.ID != req.UserID || req.User.Tenant != tenant {
		return "the request does not say the user was provisioned", nil
	}

	return "", nil
}

func testPolicySeesProvisionedUser(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, AuthWithAppTables, AuthConfig{
		Auth:    true,
		Resolve: provisioningResolver("new@lakeside.edu", "partner-1"),
		Policy: func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*signin.Decision, error) {
			unseen, err := seesProvisioned(ctx, tx, req, "partner-1")
			if err != nil || unseen != "" {
				return &signin.Decision{Outcome: signin.DenySignIn, Refusal: sessioninfo.LoginRefusalCode(unseen)}, err
			}

			return &signin.Decision{Outcome: signin.AllowSignIn}, nil
		},
	})

	id, req, err := signIn(ctx, in, lakeside("idp_new"), sessioninfo.ReasonLogin)
	if err != nil {
		t.Fatalf("first sign-in error = %v (code %q), want the policy to see the provisioned user and allow", err, sessioninfo.LoginRefusalCodeOf(err))
	}
	if sess := mustSession(ctx, t, in.Driver, id); sess.UserID != ccc.NullUUIDFromUUID(req.UserID) {
		t.Errorf("Session().UserID = %v, want the provisioned user %v", sess.UserID, req.UserID)
	}
}

func testCustomDataSeesProvisionedUser(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, AuthWithAppTables, AuthConfig{
		Auth:    true,
		Resolve: provisioningResolver("new@lakeside.edu", "partner-1"),
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

	id, _, err := signIn(ctx, in, lakeside("idp_new"), sessioninfo.ReasonLogin)
	if err != nil {
		t.Fatalf("first sign-in error = %v, want the custom session data resolver to see the provisioned user", err)
	}
	data, ok := mustSession(ctx, t, in.Driver, id).CustomData.(*CustomStringData)
	if !ok || data.CustomString != "member of partner-1" {
		t.Errorf("Session().CustomData = %#v, want the resolver's data", data)
	}
}

func testPendingRowSkipsCustomData(ctx context.Context, t *testing.T, h *AuthHarness) {
	var calls int
	in := h.New(ctx, t, AuthWithAppTables, AuthConfig{
		Auth: true,
		CustomData: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (any, error) {
			calls++

			return nil, errors.New("a resolver that looks the user up fails without one")
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
		t.Errorf("pending row = UserID %v, AuthenticatedAt %v; want no user and never authenticated", sess.UserID, sess.AuthenticatedAt)
	}
}

func testSignInUserReported(_ context.Context, t *testing.T, h *AuthHarness) {
	tests := []struct {
		name string
		// signIn runs the sign-in for the seeded users and returns its request.
		signIn func(ctx context.Context, t *testing.T, in *AuthInstance, sso, pat *dbtype.SessionUser) (*sessioninfo.NewSessionRequest, error)
		want   func(sso, pat *dbtype.SessionUser, req *sessioninfo.NewSessionRequest) *sessioninfo.SignInUser
	}{
		{
			name: "an existing link, with its tenant",
			signIn: func(ctx context.Context, t *testing.T, in *AuthInstance, sso, _ *dbtype.SessionUser) (*sessioninfo.NewSessionRequest, error) {
				t.Helper()
				if _, err := in.Driver.LinkIdentity(ctx, sso.ID, lakeside("idp_sso"), "partner-1"); err != nil {
					t.Fatalf("LinkIdentity() error = %v", err)
				}
				_, req, err := signIn(ctx, in, lakeside("idp_sso"), sessioninfo.ReasonLogin)

				return req, err
			},
			want: func(sso, _ *dbtype.SessionUser, _ *sessioninfo.NewSessionRequest) *sessioninfo.SignInUser {
				return &sessioninfo.SignInUser{ID: sso.ID, Username: sso.Username, Source: sessioninfo.UserExistingLink, Tenant: "partner-1"}
			},
		},
		{
			name: "a link the resolver made",
			signIn: func(ctx context.Context, _ *testing.T, in *AuthInstance, _, _ *dbtype.SessionUser) (*sessioninfo.NewSessionRequest, error) {
				_, req, err := signIn(ctx, in, lakeside("idp_link"), sessioninfo.ReasonLogin)

				return req, err
			},
			want: func(sso, _ *dbtype.SessionUser, _ *sessioninfo.NewSessionRequest) *sessioninfo.SignInUser {
				return &sessioninfo.SignInUser{ID: sso.ID, Username: sso.Username, Source: sessioninfo.UserNewLink, Tenant: "partner-2"}
			},
		},
		{
			name: "a user the resolver provisioned",
			signIn: func(ctx context.Context, _ *testing.T, in *AuthInstance, _, _ *dbtype.SessionUser) (*sessioninfo.NewSessionRequest, error) {
				_, req, err := signIn(ctx, in, lakeside("idp_new"), sessioninfo.ReasonLogin)

				return req, err
			},
			want: func(_, _ *dbtype.SessionUser, req *sessioninfo.NewSessionRequest) *sessioninfo.SignInUser {
				return &sessioninfo.SignInUser{ID: req.UserID, Username: "new@lakeside.edu", Source: sessioninfo.UserProvisioned, Tenant: "partner-3"}
			},
		},
		{
			name: "a password sign-in's named user",
			signIn: func(ctx context.Context, _ *testing.T, in *AuthInstance, _, pat *dbtype.SessionUser) (*sessioninfo.NewSessionRequest, error) {
				return passwordSignIn(ctx, in, pat, sessioninfo.ReasonLogin)
			},
			want: func(_, pat *dbtype.SessionUser, _ *sessioninfo.NewSessionRequest) *sessioninfo.SignInUser {
				return &sessioninfo.SignInUser{ID: pat.ID, Username: pat.Username, HasPassword: true, Source: sessioninfo.UserNamed}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			var sso *dbtype.SessionUser
			in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Resolve: func(_ context.Context, _ HookTx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
				if req.Identity.Subject == "idp_link" {
					return &signin.Resolution{Outcome: signin.LinkIdentity, UserID: sso.ID, Tenant: "partner-2"}, nil
				}

				return &signin.Resolution{Outcome: signin.ProvisionUser, NewUser: &signin.NewUser{Username: "new@lakeside.edu"}, Tenant: "partner-3"}, nil
			}})
			sso = createUser(ctx, t, in.Driver, "sso@lakeside.edu")
			pat := passwordUser(ctx, t, in.Driver, "pat@lakeside.edu")

			req, err := tt.signIn(ctx, t, in, sso, pat)
			if err != nil {
				t.Fatalf("sign-in error = %v", err)
			}
			if diff := cmp.Diff(tt.want(sso, pat, req), req.User); diff != "" {
				t.Errorf("NewSessionRequest.User mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
