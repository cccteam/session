package drivertest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
)

// lakeside is an external identity at the WorkOS connection conn_lakeside.
func lakeside(subject string) *sessioninfo.Identity {
	return &sessioninfo.Identity{
		Method: sessioninfo.MethodWorkOS, Connection: "conn_lakeside", Subject: subject,
		Email: subject + "@lakeside.edu", EmailVerified: true, IdPAMR: []string{"mfa"},
	}
}

// signIn inserts a session for identity with reason, as a sign-in method would.
func signIn(ctx context.Context, d AccountsDriver, identity *sessioninfo.Identity, reason sessioninfo.NewSessionReason) (ccc.UUID, *sessioninfo.NewSessionRequest, error) {
	req := &sessioninfo.NewSessionRequest{Reason: reason, Username: identity.Email, Identity: identity}

	id, err := d.InsertSession(ctx, newInsertSession(identity.Email), req)
	if err != nil {
		return ccc.NilUUID, req, errors.Wrap(err, "InsertSession()")
	}

	return id, req, nil
}

// passwordUser creates an account that has a password.
func passwordUser(ctx context.Context, t *testing.T, d AccountsDriver, username string) *dbtype.SessionUser {
	t.Helper()

	hash, err := securehash.New(securehash.Argon2()).Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	user, err := d.CreateUser(ctx, &dbtype.InsertSessionUser{Username: username, PasswordHash: hash}, nil)
	if err != nil {
		t.Fatalf("CreateUser(%q) error = %v", username, err)
	}

	return user
}

func mustLink(ctx context.Context, t *testing.T, d AccountsDriver, userID ccc.UUID, identity *sessioninfo.Identity) *dbtype.SessionIdentity {
	t.Helper()

	link, err := d.LinkIdentity(ctx, userID, identity, "")
	if err != nil {
		t.Fatalf("LinkIdentity() error = %v", err)
	}

	return link
}

// assertNoLink fails unless identity is unlinked.
func assertNoLink(ctx context.Context, t *testing.T, d AccountsDriver, identity *sessioninfo.Identity) {
	t.Helper()

	if _, err := d.Identity(ctx, identity.Method, identity.Connection, identity.Subject); !httpio.HasNotFound(err) {
		t.Errorf("Identity() error = %v, want NotFound: nothing may be linked", err)
	}
}

// assertRefused fails unless err is a refusal with code and cause.
func assertRefused(t *testing.T, err error, code sessioninfo.LoginRefusalCode, cause error) {
	t.Helper()

	if err == nil {
		t.Fatal("sign-in error = nil, want a refusal")
	}
	if got := sessioninfo.LoginRefusalCodeOf(err); got != code {
		t.Errorf("refusal code = %q, want %q: %v", got, code, err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("sign-in error = %v, want cause %v", err, cause)
	}
	if !httpio.HasUnauthorized(err) {
		t.Errorf("sign-in error = %v, want Unauthorized", err)
	}
}

func testLinkedIdentitySignsIn(ctx context.Context, t *testing.T, h *AccountsHarness) {
	var resolverCalls atomic.Int32
	in := h.New(ctx, t, Accounts, AccountsConfig{AuthEvents: true, Identities: true, Resolve: func(context.Context, *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
		resolverCalls.Add(1)

		return nil, nil
	}})
	user := createUser(ctx, t, in.Driver, "jane@lakeside.edu")
	identity := lakeside("idp_jane")
	link := mustLink(ctx, t, in.Driver, user.ID, identity)

	id, req, err := signIn(ctx, in.Driver, identity, sessioninfo.ReasonLogin)
	if err != nil {
		t.Fatalf("sign-in of a linked identity error = %v", err)
	}

	if resolverCalls.Load() != 0 {
		t.Errorf("the account resolver ran %d times for a linked identity, want 0", resolverCalls.Load())
	}
	if req.UserID != user.ID {
		t.Errorf("req.UserID = %v, want the linked account %v", req.UserID, user.ID)
	}
	sess := mustSession(ctx, t, in.Driver, id)
	if sess.UserID != ccc.NullUUIDFromUUID(user.ID) || sess.Username != user.Username {
		t.Errorf("Session() = UserID %v, Username %q; want the linked account %v, %q", sess.UserID, sess.Username, user.ID, user.Username)
	}
	want := []sessioninfo.AuthEvent{{Method: sessioninfo.MethodWorkOS, Connection: "conn_lakeside", IdPAMR: []string{"mfa"}, At: time.Now()}}
	if diff := cmp.Diff(want, sess.AuthEvents, eventsOpts); diff != "" {
		t.Errorf("Session().AuthEvents mismatch (-want +got):\n%s", diff)
	}
	touched, err := in.Driver.Identity(ctx, identity.Method, identity.Connection, identity.Subject)
	if err != nil {
		t.Fatalf("Identity() error = %v", err)
	}
	if !touched.LastUsedAt.After(link.LastUsedAt) {
		t.Errorf("Identity().LastUsedAt = %v, want it moved past %v by the sign-in", touched.LastUsedAt, link.LastUsedAt)
	}
}

func testResolverOutcomes(_ context.Context, t *testing.T, h *AccountsHarness) {
	tests := []struct {
		name string
		// resolve answers for the unlinked identity, given the seeded accounts.
		resolve func(passwordless, withPassword *dbtype.SessionUser, provisioned *[]ccc.UUID) *dbtype.Resolution
		// check asserts the outcome.
		check func(t *testing.T, d AccountsDriver, err error, req *sessioninfo.NewSessionRequest, passwordless, withPassword *dbtype.SessionUser, provisioned []ccc.UUID)
	}{
		{
			name: "ProvisionAccount creates a password-less account, links the identity with its tenant, and signs in",
			resolve: func(_, _ *dbtype.SessionUser, provisioned *[]ccc.UUID) *dbtype.Resolution {
				return &dbtype.Resolution{
					Outcome: dbtype.ProvisionAccount, NewUser: &dbtype.InsertSessionUser{Username: "new@lakeside.edu"}, Tenant: "partner-1",
					OnProvisioned: func(_ context.Context, userID ccc.UUID) error {
						*provisioned = append(*provisioned, userID)

						return nil
					},
				}
			},
			check: func(t *testing.T, d AccountsDriver, err error, req *sessioninfo.NewSessionRequest, _, _ *dbtype.SessionUser, provisioned []ccc.UUID) {
				t.Helper()
				if err != nil {
					t.Fatalf("sign-in error = %v", err)
				}
				user, uerr := d.UserByUserName(t.Context(), "new@lakeside.edu")
				if uerr != nil {
					t.Fatalf("UserByUserName() error = %v, want the provisioned account", uerr)
				}
				if user.PasswordHash != nil || req.UserID != user.ID || req.Username != user.Username {
					t.Errorf("provisioned account = %+v, req = (%v, %q); want password-less, signed in", user, req.UserID, req.Username)
				}
				if len(provisioned) == 0 || provisioned[len(provisioned)-1] != user.ID {
					t.Errorf("OnProvisioned received %v, want the new account %v", provisioned, user.ID)
				}
				link, lerr := d.Identity(t.Context(), sessioninfo.MethodWorkOS, "conn_lakeside", "idp_unknown")
				if lerr != nil {
					t.Fatalf("Identity() error = %v", lerr)
				}
				if link.UserID != user.ID || link.Tenant == nil || *link.Tenant != "partner-1" || link.EmailAtLink == nil || *link.EmailAtLink != "idp_unknown@lakeside.edu" {
					t.Errorf("Identity() = %+v, want the link to the new account with tenant and email", link)
				}
			},
		},
		{
			name: "an OnProvisioned failure writes nothing",
			resolve: func(_, _ *dbtype.SessionUser, _ *[]ccc.UUID) *dbtype.Resolution {
				return &dbtype.Resolution{
					Outcome: dbtype.ProvisionAccount, NewUser: &dbtype.InsertSessionUser{Username: "new@lakeside.edu"},
					OnProvisioned: func(context.Context, ccc.UUID) error { return errors.New("app rows failed") },
				}
			},
			check: func(t *testing.T, d AccountsDriver, err error, _ *sessioninfo.NewSessionRequest, _, _ *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				if err == nil {
					t.Fatal("sign-in error = nil, want the OnProvisioned failure")
				}
				if _, uerr := d.UserByUserName(t.Context(), "new@lakeside.edu"); !httpio.HasNotFound(uerr) {
					t.Errorf("UserByUserName() error = %v, want NotFound: the account must not be created", uerr)
				}
				assertNoLink(t.Context(), t, d, lakeside("idp_unknown"))
			},
		},
		{
			name: "LinkIdentity links a password-less account and signs in",
			resolve: func(passwordless, _ *dbtype.SessionUser, _ *[]ccc.UUID) *dbtype.Resolution {
				return &dbtype.Resolution{Outcome: dbtype.LinkIdentity, UserID: passwordless.ID}
			},
			check: func(t *testing.T, d AccountsDriver, err error, req *sessioninfo.NewSessionRequest, passwordless, _ *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				if err != nil {
					t.Fatalf("sign-in error = %v", err)
				}
				if req.UserID != passwordless.ID {
					t.Errorf("req.UserID = %v, want %v", req.UserID, passwordless.ID)
				}
				if link, lerr := d.Identity(t.Context(), sessioninfo.MethodWorkOS, "conn_lakeside", "idp_unknown"); lerr != nil || link.UserID != passwordless.ID {
					t.Errorf("Identity() = %+v, %v; want the link to %v", link, lerr, passwordless.ID)
				}
			},
		},
		{
			name: "LinkIdentity is refused for an account that has a password",
			resolve: func(_, withPassword *dbtype.SessionUser, _ *[]ccc.UUID) *dbtype.Resolution {
				return &dbtype.Resolution{Outcome: dbtype.LinkIdentity, UserID: withPassword.ID}
			},
			check: func(t *testing.T, d AccountsDriver, err error, _ *sessioninfo.NewSessionRequest, _, _ *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedIdentityRejected, dbtype.ErrLinkRequiresConfirmation)
				assertNoLink(t.Context(), t, d, lakeside("idp_unknown"))
			},
		},
		{
			name: "LinkIdentity links an account that has a password when the connection is trusted for linking",
			resolve: func(_, withPassword *dbtype.SessionUser, _ *[]ccc.UUID) *dbtype.Resolution {
				return &dbtype.Resolution{Outcome: dbtype.LinkIdentity, UserID: withPassword.ID, TrustedForLinking: true}
			},
			check: func(t *testing.T, _ AccountsDriver, err error, req *sessioninfo.NewSessionRequest, _, withPassword *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				if err != nil || req.UserID != withPassword.ID {
					t.Errorf("sign-in = %v, %v; want the account %v", req.UserID, err, withPassword.ID)
				}
			},
		},
		{
			name: "RequireConfirmation reports the pending confirmation and writes nothing",
			resolve: func(_, withPassword *dbtype.SessionUser, _ *[]ccc.UUID) *dbtype.Resolution {
				return &dbtype.Resolution{Outcome: dbtype.RequireConfirmation, UserID: withPassword.ID, Tenant: "partner-1"}
			},
			check: func(t *testing.T, d AccountsDriver, err error, _ *sessioninfo.NewSessionRequest, _, withPassword *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				var pending *dbtype.PendingSignInError
				if !errors.As(err, &pending) {
					t.Fatalf("sign-in error = %v, want a PendingSignInError", err)
				}
				want := dbtype.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(withPassword.ID), Username: withPassword.Username, Tenant: "partner-1"}
				if *pending != want {
					t.Errorf("PendingSignInError = %+v, want %+v", *pending, want)
				}
				assertNoLink(t.Context(), t, d, lakeside("idp_unknown"))
			},
		},
		{
			name: "RejectIdentity refuses with the resolver's code and writes nothing",
			resolve: func(_, _ *dbtype.SessionUser, _ *[]ccc.UUID) *dbtype.Resolution {
				return &dbtype.Resolution{Outcome: dbtype.RejectIdentity, Refusal: "not_invited"}
			},
			check: func(t *testing.T, d AccountsDriver, err error, _ *sessioninfo.NewSessionRequest, _, _ *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				assertRefused(t, err, "not_invited", dbtype.ErrIdentityRejected)
				assertNoLink(t.Context(), t, d, lakeside("idp_unknown"))
			},
		},
		{
			name: "an empty Resolution rejects with the default code",
			resolve: func(_, _ *dbtype.SessionUser, _ *[]ccc.UUID) *dbtype.Resolution {
				return nil
			},
			check: func(t *testing.T, _ AccountsDriver, err error, _ *sessioninfo.NewSessionRequest, _, _ *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedIdentityRejected, dbtype.ErrIdentityRejected)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			var (
				passwordless, withPassword *dbtype.SessionUser
				provisioned                []ccc.UUID
				mu                         sync.Mutex
			)
			in := h.New(ctx, t, Accounts, AccountsConfig{Identities: true, Resolve: func(context.Context, *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
				mu.Lock()
				defer mu.Unlock()

				return tt.resolve(passwordless, withPassword, &provisioned), nil
			}})
			passwordless = createUser(ctx, t, in.Driver, "sso@lakeside.edu")
			withPassword = passwordUser(ctx, t, in.Driver, "pat@lakeside.edu")

			_, req, err := signIn(ctx, in.Driver, lakeside("idp_unknown"), sessioninfo.ReasonLogin)

			mu.Lock()
			defer mu.Unlock()
			tt.check(t, in.Driver, err, req, passwordless, withPassword, provisioned)
		})
	}
}

func testSignInPolicy(_ context.Context, t *testing.T, h *AccountsHarness) {
	tests := []struct {
		name     string
		decision *dbtype.SignInDecision
		reason   sessioninfo.NewSessionReason
		password bool
		// provision makes the identity unlinked and provisioned by the resolver.
		provision bool
		check     func(t *testing.T, d AccountsDriver, err error, user *dbtype.SessionUser)
	}{
		{
			name:     "AllowSignIn signs in",
			decision: &dbtype.SignInDecision{Outcome: dbtype.AllowSignIn},
			reason:   sessioninfo.ReasonLogin,
			check: func(t *testing.T, _ AccountsDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				if err != nil {
					t.Errorf("sign-in error = %v, want allowed", err)
				}
			},
		},
		{
			name:     "DenySignIn refuses with the policy's code",
			decision: &dbtype.SignInDecision{Outcome: dbtype.DenySignIn, Refusal: "sso_required"},
			reason:   sessioninfo.ReasonLogin,
			check: func(t *testing.T, _ AccountsDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, "sso_required", dbtype.ErrSignInDenied)
			},
		},
		{
			name:   "no decision denies with the default code",
			reason: sessioninfo.ReasonLogin,
			check: func(t *testing.T, _ AccountsDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedByPolicy, dbtype.ErrSignInDenied)
			},
		},
		{
			name:     "the policy decides a password sign-in too",
			decision: &dbtype.SignInDecision{Outcome: dbtype.DenySignIn},
			reason:   sessioninfo.ReasonLogin,
			password: true,
			check: func(t *testing.T, _ AccountsDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedByPolicy, dbtype.ErrSignInDenied)
			},
		},
		{
			name:     "RequireMFA reports the pending MFA for the account",
			decision: &dbtype.SignInDecision{Outcome: dbtype.RequireMFA},
			reason:   sessioninfo.ReasonLogin,
			check: func(t *testing.T, _ AccountsDriver, err error, user *dbtype.SessionUser) {
				t.Helper()
				var pending *dbtype.PendingSignInError
				if !errors.As(err, &pending) {
					t.Fatalf("sign-in error = %v, want a PendingSignInError", err)
				}
				want := dbtype.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(user.ID), Username: user.Username}
				if *pending != want {
					t.Errorf("PendingSignInError = %+v, want %+v", *pending, want)
				}
			},
		},
		{
			name:      "a denied sign-in leaves no provisioned account or link behind",
			decision:  &dbtype.SignInDecision{Outcome: dbtype.DenySignIn},
			reason:    sessioninfo.ReasonLogin,
			provision: true,
			check: func(t *testing.T, d AccountsDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedByPolicy, dbtype.ErrSignInDenied)
				if _, uerr := d.UserByUserName(t.Context(), "fresh@lakeside.edu"); !httpio.HasNotFound(uerr) {
					t.Errorf("UserByUserName() error = %v, want NotFound", uerr)
				}
				assertNoLink(t.Context(), t, d, lakeside("idp_fresh"))
			},
		},
		{
			name:      "an MFA wait on a provisioning sign-in names no account and writes nothing",
			decision:  &dbtype.SignInDecision{Outcome: dbtype.RequireMFA},
			reason:    sessioninfo.ReasonLogin,
			provision: true,
			check: func(t *testing.T, d AccountsDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				var pending *dbtype.PendingSignInError
				if !errors.As(err, &pending) || pending.Reason != sessioninfo.PendingMFA || pending.UserID.Valid {
					t.Fatalf("sign-in error = %v, want a PendingSignInError for MFA with no account", err)
				}
				if _, uerr := d.UserByUserName(t.Context(), "fresh@lakeside.edu"); !httpio.HasNotFound(uerr) {
					t.Errorf("UserByUserName() error = %v, want NotFound", uerr)
				}
			},
		},
		{
			name:     "a step-up completion is not decided again",
			decision: &dbtype.SignInDecision{Outcome: dbtype.RequireMFA},
			reason:   sessioninfo.ReasonStepUp,
			check: func(t *testing.T, _ AccountsDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				if err != nil {
					t.Errorf("step-up sign-in error = %v, want the session", err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			in := h.New(ctx, t, Accounts, AccountsConfig{
				Identities: true,
				Resolve: func(context.Context, *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
					return &dbtype.Resolution{Outcome: dbtype.ProvisionAccount, NewUser: &dbtype.InsertSessionUser{Username: "fresh@lakeside.edu"}}, nil
				},
				Policy: func(_ context.Context, req *sessioninfo.NewSessionRequest) (*dbtype.SignInDecision, error) {
					if req.UserID.IsNil() {
						return nil, errors.New("the policy ran before the account was known")
					}

					return tt.decision, nil
				},
			})
			user := createUser(ctx, t, in.Driver, "jane@lakeside.edu")

			var err error
			switch {
			case tt.provision:
				_, _, err = signIn(ctx, in.Driver, lakeside("idp_fresh"), tt.reason)
			case tt.password:
				_, err = in.Driver.InsertSession(ctx, newInsertSession(user.Username), &sessioninfo.NewSessionRequest{
					Reason: tt.reason, Username: user.Username, UserID: user.ID,
					Identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String()},
				})
			default:
				mustLink(ctx, t, in.Driver, user.ID, lakeside("idp_jane"))
				_, _, err = signIn(ctx, in.Driver, lakeside("idp_jane"), tt.reason)
			}

			tt.check(t, in.Driver, err, user)
		})
	}
}

func testDisabledAccountRefused(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, Accounts, AccountsConfig{Identities: true})
	user := createUser(ctx, t, in.Driver, "gone@lakeside.edu")
	mustLink(ctx, t, in.Driver, user.ID, lakeside("idp_gone"))
	if err := in.Driver.DeactivateUser(ctx, user.ID); err != nil {
		t.Fatalf("DeactivateUser() error = %v", err)
	}

	_, _, err := signIn(ctx, in.Driver, lakeside("idp_gone"), sessioninfo.ReasonLogin)

	assertRefused(t, err, sessioninfo.RefusedAccountDisabled, dbtype.ErrAccountDisabled)
}

func testIdentitiesNotConfigured(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, Accounts, AccountsConfig{Accounts: true})

	if in.Driver.IdentitiesEnabled() {
		t.Error("IdentitiesEnabled() = true without an identities configuration")
	}
	if _, _, err := signIn(ctx, in.Driver, lakeside("idp_any"), sessioninfo.ReasonLogin); !errors.Is(err, dbtype.ErrIdentitiesNotConfigured) {
		t.Errorf("sign-in error = %v, want ErrIdentitiesNotConfigured", err)
	}
}

func testConcurrentFirstSignIn(ctx context.Context, t *testing.T, h *AccountsHarness) {
	var user *dbtype.SessionUser
	in := h.New(ctx, t, Accounts, AccountsConfig{Identities: true, Resolve: func(context.Context, *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
		// Hold the window between the lookup and the link open, so the sign-ins race.
		time.Sleep(100 * time.Millisecond)

		return &dbtype.Resolution{Outcome: dbtype.LinkIdentity, UserID: user.ID}, nil
	}})
	user = createUser(ctx, t, in.Driver, "race@lakeside.edu")

	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			_, req, err := signIn(ctx, in.Driver, lakeside("idp_race"), sessioninfo.ReasonLogin)
			if err == nil && req.UserID != user.ID {
				err = errors.Newf("signed in to %v, want %v", req.UserID, user.ID)
			}
			errs[i] = err
		})
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("sign-in %d error = %v, want every racing sign-in to succeed", i, err)
		}
	}
	links, err := in.Driver.IdentitiesByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("IdentitiesByUser() error = %v", err)
	}
	if len(links) != 1 {
		t.Errorf("IdentitiesByUser() = %d links, want exactly 1", len(links))
	}
}

func testLinkManagement(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, Accounts, AccountsConfig{Identities: true})
	sso := createUser(ctx, t, in.Driver, "sso@lakeside.edu")
	pat := passwordUser(ctx, t, in.Driver, "pat@lakeside.edu")

	first := mustLink(ctx, t, in.Driver, sso.ID, lakeside("idp_a"))
	if _, err := in.Driver.LinkIdentity(ctx, pat.ID, lakeside("idp_a"), ""); !httpio.HasConflict(err) {
		t.Errorf("LinkIdentity() of a linked identity error = %v, want Conflict", err)
	}
	if _, err := in.Driver.LinkIdentity(ctx, sso.ID, &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: sso.ID.String()}, ""); !httpio.HasBadRequest(err) {
		t.Errorf("LinkIdentity() of a password identity error = %v, want BadRequest", err)
	}

	err := in.Driver.UnlinkIdentity(ctx, first.ID)
	if !errors.Is(err, dbtype.ErrLastSignInMethod) || !httpio.HasConflict(err) {
		t.Errorf("UnlinkIdentity() of a password-less account's only identity error = %v, want ErrLastSignInMethod (Conflict)", err)
	}

	second := mustLink(ctx, t, in.Driver, sso.ID, &sessioninfo.Identity{Method: sessioninfo.MethodAzure, Connection: "tenant-1", Subject: "oid-1"})
	links, err := in.Driver.IdentitiesByUser(ctx, sso.ID)
	if err != nil || len(links) != 2 || links[0].ID != first.ID || links[1].ID != second.ID {
		t.Fatalf("IdentitiesByUser() = %v, %v; want both links, oldest first", links, err)
	}
	if err := in.Driver.UnlinkIdentity(ctx, first.ID); err != nil {
		t.Errorf("UnlinkIdentity() with another identity left error = %v", err)
	}
	if err := in.Driver.UnlinkIdentity(ctx, second.ID); !errors.Is(err, dbtype.ErrLastSignInMethod) {
		t.Errorf("UnlinkIdentity() of the remaining identity error = %v, want ErrLastSignInMethod", err)
	}

	patLink := mustLink(ctx, t, in.Driver, pat.ID, lakeside("idp_pat"))
	if err := in.Driver.UnlinkIdentity(ctx, patLink.ID); err != nil {
		t.Errorf("UnlinkIdentity() of an account that has a password error = %v, want removed", err)
	}
	if err := in.Driver.UnlinkIdentity(ctx, patLink.ID); !httpio.HasNotFound(err) {
		t.Errorf("UnlinkIdentity() of a removed link error = %v, want NotFound", err)
	}
}

func testDeleteUserDeletesLinks(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, Accounts, AccountsConfig{Identities: true})
	sso := createUser(ctx, t, in.Driver, "gone@lakeside.edu")
	other := createUser(ctx, t, in.Driver, "stays@lakeside.edu")
	mustLink(ctx, t, in.Driver, sso.ID, lakeside("idp_gone"))
	mustLink(ctx, t, in.Driver, sso.ID, &sessioninfo.Identity{Method: sessioninfo.MethodAzure, Connection: "tenant-1", Subject: "oid-gone"})
	kept := mustLink(ctx, t, in.Driver, other.ID, lakeside("idp_stays"))

	if err := in.Driver.DeleteUser(ctx, sso.ID); err != nil {
		t.Fatalf("DeleteUser() of a linked account error = %v", err)
	}

	assertNoLink(ctx, t, in.Driver, lakeside("idp_gone"))
	if links, err := in.Driver.IdentitiesByUser(ctx, sso.ID); err != nil || len(links) != 0 {
		t.Errorf("IdentitiesByUser() of the deleted account = %v, %v; want none", links, err)
	}
	if link, err := in.Driver.Identity(ctx, sessioninfo.MethodWorkOS, "conn_lakeside", "idp_stays"); err != nil || link.ID != kept.ID {
		t.Errorf("Identity() of another account's link = %v, %v; want it kept", link, err)
	}
	if err := in.Driver.DeleteUser(ctx, sso.ID); !httpio.HasNotFound(err) {
		t.Errorf("DeleteUser() of a deleted account error = %v, want NotFound", err)
	}
}

func testDestroyUserSessions(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, Accounts, AccountsConfig{Accounts: true, Impersonation: true})
	jane := createUser(ctx, t, in.Driver, "jane@lakeside.edu")
	other := createUser(ctx, t, in.Driver, "other@lakeside.edu")

	start := func(user *dbtype.SessionUser, username string) ccc.UUID {
		t.Helper()
		id, err := in.Driver.InsertSession(ctx, newInsertSession(username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: username, UserID: user.ID})
		if err != nil {
			t.Fatalf("InsertSession() error = %v", err)
		}

		return id
	}
	impersonate := func(actor string, principal accesstypes.Principal, userID ccc.UUID, username string) ccc.UUID {
		t.Helper()
		now := time.Now()
		imp := dbtype.NewInsertImpersonation(&sessioninfo.Impersonation{Actor: actor, Principal: principal, StartedAt: now, ExpiresAt: now.Add(time.Hour)})
		id, err := in.Driver.InsertImpersonatedSession(ctx, newInsertSession(username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: username, UserID: userID}, imp)
		if err != nil {
			t.Fatalf("InsertImpersonatedSession() error = %v", err)
		}

		return id
	}

	// A session row carrying jane's username but another account's ID (a rename in
	// flight, a recycled name) is not jane's: the key is UserId.
	janeOwn := start(jane, jane.Username)
	janeRenamed := start(jane, "jane-old@lakeside.edu")
	borrowedName := start(other, jane.Username)
	ofJane := impersonate("admin@lakeside.edu", accesstypes.UserPrincipal(accesstypes.User(jane.Username)), jane.ID, jane.Username)
	byJane := impersonate(jane.Username, accesstypes.RolePrincipal("Viewer"), ccc.NilUUID, jane.Username)

	if err := in.Driver.DestroyUserSessions(ctx, jane.ID); err != nil {
		t.Fatalf("DestroyUserSessions() error = %v", err)
	}

	for _, tc := range []struct {
		name        string
		id          ccc.UUID
		wantExpired bool
	}{
		{"jane's own session", janeOwn, true},
		{"jane's session under an old username", janeRenamed, true},
		{"the user-principal impersonation of jane", ofJane, true},
		{"the session jane holds as a local actor", byJane, true},
		{"another account's session under jane's username", borrowedName, false},
	} {
		if got := mustSession(ctx, t, in.Driver, tc.id).Expired; got != tc.wantExpired {
			t.Errorf("%s: Expired = %v, want %v", tc.name, got, tc.wantExpired)
		}
	}
	for _, id := range []ccc.UUID{ofJane, byJane} {
		imp := mustSession(ctx, t, in.Driver, id).Impersonation
		if imp == nil || imp.EndReason == nil || *imp.EndReason != string(sessioninfo.ImpersonationEndedByRevocation) {
			t.Errorf("impersonation record of %v = %+v, want ended Revoked", id, imp)
		}
	}
}

func testAppendAuthEvent(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, Accounts, AccountsConfig{Identities: true, AuthEvents: true})
	user := createUser(ctx, t, in.Driver, "jane@lakeside.edu")
	mustLink(ctx, t, in.Driver, user.ID, lakeside("idp_jane"))

	id, _, err := signIn(ctx, in.Driver, lakeside("idp_jane"), sessioninfo.ReasonLogin)
	if err != nil {
		t.Fatalf("sign-in error = %v", err)
	}

	stepUp := time.Now().Add(time.Minute).Truncate(time.Millisecond)
	if err := in.Driver.AppendAuthEvent(ctx, id, &sessioninfo.AuthEvent{Method: "email-otp", At: stepUp}); err != nil {
		t.Fatalf("AppendAuthEvent() error = %v", err)
	}

	sess := mustSession(ctx, t, in.Driver, id)
	want := []sessioninfo.AuthEvent{
		{Method: sessioninfo.MethodWorkOS, Connection: "conn_lakeside", IdPAMR: []string{"mfa"}, At: time.Now()},
		{Method: "email-otp", At: stepUp},
	}
	if diff := cmp.Diff(want, sess.AuthEvents, eventsOpts); diff != "" {
		t.Errorf("Session().AuthEvents mismatch (-want +got):\n%s", diff)
	}
	if sess.AuthenticatedAt == nil || !sess.AuthenticatedAt.Equal(stepUp) {
		t.Errorf("Session().AuthenticatedAt = %v, want the step-up time %v", sess.AuthenticatedAt, stepUp)
	}

	h.DeleteSession(ctx, t, in.Raw, id)
	if err := in.Driver.AppendAuthEvent(ctx, id, &sessioninfo.AuthEvent{Method: "email-otp"}); !httpio.HasNotFound(err) {
		t.Errorf("AppendAuthEvent() on a missing session error = %v, want NotFound", err)
	}
}
