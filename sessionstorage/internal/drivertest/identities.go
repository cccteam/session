package drivertest

import (
	"context"
	"fmt"
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
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// lakeside is an external identity at the WorkOS connection conn_lakeside.
func lakeside(subject string) *sessioninfo.Identity {
	return &sessioninfo.Identity{
		Method: sessioninfo.MethodWorkOS, Connection: "conn_lakeside", Subject: subject,
		Email: subject + "@lakeside.edu", EmailVerified: true, IDPAMR: []string{"mfa"},
	}
}

// riverside is an external identity at another WorkOS connection, conn_riverside.
func riverside(subject string) *sessioninfo.Identity {
	return &sessioninfo.Identity{
		Method: sessioninfo.MethodWorkOS, Connection: "conn_riverside", Subject: subject,
		Email: subject + "@lakeside.edu", EmailVerified: true,
	}
}

// signIn establishes a session for identity with reason through the instance's sign-in
// flow, as a sign-in method would.
func signIn(ctx context.Context, in *AuthInstance, identity *sessioninfo.Identity, reason sessioninfo.NewSessionReason) (ccc.UUID, *sessioninfo.NewSessionRequest, error) {
	req := &sessioninfo.NewSessionRequest{Reason: reason, Username: identity.Email, Identity: identity}

	id, err := in.SignIn(ctx, newInsertSession(identity.Email), req)
	if err != nil {
		return ccc.NilUUID, req, errors.Wrap(err, "AuthInstance.SignIn()")
	}

	return id, req, nil
}

// passwordSignIn establishes a session for user's password identity with reason through
// the instance's sign-in flow.
func passwordSignIn(ctx context.Context, in *AuthInstance, user *dbtype.SessionUser, reason sessioninfo.NewSessionReason) (*sessioninfo.NewSessionRequest, error) {
	req := &sessioninfo.NewSessionRequest{
		Reason: reason, Username: user.Username, UserID: user.ID,
		Identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String()},
	}
	if _, err := in.SignIn(ctx, newInsertSession(user.Username), req); err != nil {
		return req, errors.Wrap(err, "AuthInstance.SignIn()")
	}

	return req, nil
}

// passwordUser creates a user that has a password.
func passwordUser(ctx context.Context, t *testing.T, d AuthDriver, username string) *dbtype.SessionUser {
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

func mustLink(ctx context.Context, t *testing.T, d AuthDriver, userID ccc.UUID, identity *sessioninfo.Identity) *dbtype.SessionIdentity {
	t.Helper()

	link, err := d.LinkIdentity(ctx, userID, identity, "")
	if err != nil {
		t.Fatalf("LinkIdentity() error = %v", err)
	}

	return link
}

// assertNoLink fails unless identity is unlinked.
func assertNoLink(ctx context.Context, t *testing.T, d AuthDriver, identity *sessioninfo.Identity) {
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

func testLinkedIdentitySignsIn(ctx context.Context, t *testing.T, h *AuthHarness) {
	var resolverCalls atomic.Int32
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, AuthEvents: true, Resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		resolverCalls.Add(1)

		return nil, nil
	}})
	user := createUser(ctx, t, in.Driver, "jane@lakeside.edu")
	identity := lakeside("idp_jane")
	link := mustLink(ctx, t, in.Driver, user.ID, identity)

	id, req, err := signIn(ctx, in, identity, sessioninfo.ReasonLogin)
	if err != nil {
		t.Fatalf("sign-in of a linked identity error = %v", err)
	}

	if resolverCalls.Load() != 0 {
		t.Errorf("the user resolver ran %d times for a linked identity, want 0", resolverCalls.Load())
	}
	if req.UserID != user.ID {
		t.Errorf("req.UserID = %v, want the linked user %v", req.UserID, user.ID)
	}
	sess := mustSession(ctx, t, in.Driver, id)
	if sess.UserID != ccc.NullUUIDFromUUID(user.ID) || sess.Username != user.Username {
		t.Errorf("Session() = UserID %v, Username %q; want the linked user %v, %q", sess.UserID, sess.Username, user.ID, user.Username)
	}
	want := []sessioninfo.AuthEvent{{Method: sessioninfo.MethodWorkOS, Connection: "conn_lakeside", IDPAMR: []string{"mfa"}, At: sess.CreatedAt}}
	if diff := cmp.Diff(want, sess.AuthEvents, eventsOpts); diff != "" {
		t.Errorf("Session().AuthEvents mismatch (-want +got):\n%s", diff)
	}
	// The resolution touches the link and commits before the session is inserted.
	touched, err := in.Driver.Identity(ctx, identity.Method, identity.Connection, identity.Subject)
	if err != nil {
		t.Fatalf("Identity() error = %v", err)
	}
	if !touched.LastUsedAt.After(link.LastUsedAt) || touched.LastUsedAt.After(sess.CreatedAt) {
		t.Errorf("Identity().LastUsedAt = %v, want it moved past %v by the sign-in's resolution, no later than the session's creation %v", touched.LastUsedAt, link.LastUsedAt, sess.CreatedAt)
	}
}

func testResolverOutcomes(_ context.Context, t *testing.T, h *AuthHarness) {
	tests := []struct {
		name string
		// resolve answers for the unlinked identity, given the seeded users.
		resolve func(passwordless, withPassword *dbtype.SessionUser, provisioned *[]ccc.UUID) *signin.Resolution
		// check asserts the outcome.
		check func(t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, passwordless, withPassword *dbtype.SessionUser, provisioned []ccc.UUID)
	}{
		{
			name: "ProvisionUser creates a password-less user, links the identity with its tenant, and signs in",
			resolve: func(_, _ *dbtype.SessionUser, provisioned *[]ccc.UUID) *signin.Resolution {
				return signin.Provision(&signin.NewUser{Username: "new@lakeside.edu"}, func(_ context.Context, userID ccc.UUID) error {
					*provisioned = append(*provisioned, userID)

					return nil
				}, signin.Tenant("partner-1"))
			},
			check: func(t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, _, _ *dbtype.SessionUser, provisioned []ccc.UUID) {
				t.Helper()
				if err != nil {
					t.Fatalf("sign-in error = %v", err)
				}
				user, uerr := d.UserByUserName(t.Context(), "new@lakeside.edu")
				if uerr != nil {
					t.Fatalf("UserByUserName() error = %v, want the provisioned user", uerr)
				}
				if user.PasswordHash != nil || req.UserID != user.ID || req.Username != user.Username {
					t.Errorf("provisioned user = %+v, req = (%v, %q); want password-less, signed in", user, req.UserID, req.Username)
				}
				if len(provisioned) == 0 || provisioned[len(provisioned)-1] != user.ID {
					t.Errorf("OnProvisioned received %v, want the new user %v", provisioned, user.ID)
				}
				link, lerr := d.Identity(t.Context(), sessioninfo.MethodWorkOS, "conn_lakeside", "idp_unknown")
				if lerr != nil {
					t.Fatalf("Identity() error = %v", lerr)
				}
				if link.UserID != user.ID || link.Tenant == nil || *link.Tenant != "partner-1" || link.EmailAtLink == nil || *link.EmailAtLink != "idp_unknown@lakeside.edu" {
					t.Errorf("Identity() = %+v, want the link to the new user with tenant and email", link)
				}
			},
		},
		{
			name: "an OnProvisioned failure writes nothing",
			resolve: func(_, _ *dbtype.SessionUser, _ *[]ccc.UUID) *signin.Resolution {
				return signin.Provision(&signin.NewUser{Username: "new@lakeside.edu"}, func(context.Context, ccc.UUID) error { return errors.New("app rows failed") })
			},
			check: func(t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, _, _ *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				if err == nil {
					t.Fatal("sign-in error = nil, want the OnProvisioned failure")
				}
				if _, uerr := d.UserByUserName(t.Context(), "new@lakeside.edu"); !httpio.HasNotFound(uerr) {
					t.Errorf("UserByUserName() error = %v, want NotFound: the user must not be created", uerr)
				}
				assertNoLink(t.Context(), t, d, lakeside("idp_unknown"))
			},
		},
		{
			name: "LinkIdentity links a password-less user and signs in",
			resolve: func(passwordless, _ *dbtype.SessionUser, _ *[]ccc.UUID) *signin.Resolution {
				return signin.Link(passwordless.ID, false)
			},
			check: func(t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, passwordless, _ *dbtype.SessionUser, _ []ccc.UUID) {
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
			name: "LinkIdentity is refused for a user that has a password",
			resolve: func(_, withPassword *dbtype.SessionUser, _ *[]ccc.UUID) *signin.Resolution {
				return signin.Link(withPassword.ID, false)
			},
			check: func(t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, _, _ *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedIdentityRejected, signin.ErrLinkRequiresConfirmation)
				assertNoLink(t.Context(), t, d, lakeside("idp_unknown"))
			},
		},
		{
			name: "LinkIdentity links a user that has a password when the connection is trusted for linking",
			resolve: func(_, withPassword *dbtype.SessionUser, _ *[]ccc.UUID) *signin.Resolution {
				return signin.Link(withPassword.ID, true)
			},
			check: func(t *testing.T, _ AuthDriver, err error, req *sessioninfo.NewSessionRequest, _, withPassword *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				if err != nil || req.UserID != withPassword.ID {
					t.Errorf("sign-in = %v, %v; want the user %v", req.UserID, err, withPassword.ID)
				}
			},
		},
		{
			name: "RequireConfirmation reports the pending confirmation and writes nothing",
			resolve: func(_, withPassword *dbtype.SessionUser, _ *[]ccc.UUID) *signin.Resolution {
				return signin.Confirm(withPassword.ID, signin.Tenant("partner-1"))
			},
			check: func(t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, _, withPassword *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				var pending *signin.PendingSignInError
				if !errors.As(err, &pending) {
					t.Fatalf("sign-in error = %v, want a PendingSignInError", err)
				}
				want := signin.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(withPassword.ID), Username: withPassword.Username, Tenant: "partner-1"}
				if diff := cmp.Diff(want, *pending, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("PendingSignInError mismatch (-want +got):\n%s", diff)
				}
				assertNoLink(t.Context(), t, d, lakeside("idp_unknown"))
			},
		},
		{
			name: "RejectIdentity refuses with the resolver's code and writes nothing",
			resolve: func(_, _ *dbtype.SessionUser, _ *[]ccc.UUID) *signin.Resolution {
				return signin.Reject("not_invited")
			},
			check: func(t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, _, _ *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				assertRefused(t, err, "not_invited", signin.ErrIdentityRejected)
				assertNoLink(t.Context(), t, d, lakeside("idp_unknown"))
			},
		},
		{
			name: "an empty Resolution rejects with the default code",
			resolve: func(_, _ *dbtype.SessionUser, _ *[]ccc.UUID) *signin.Resolution {
				return nil
			},
			check: func(t *testing.T, _ AuthDriver, err error, _ *sessioninfo.NewSessionRequest, _, _ *dbtype.SessionUser, _ []ccc.UUID) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedIdentityRejected, signin.ErrIdentityRejected)
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
			in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
				mu.Lock()
				defer mu.Unlock()

				return tt.resolve(passwordless, withPassword, &provisioned), nil
			}})
			passwordless = createUser(ctx, t, in.Driver, "sso@lakeside.edu")
			withPassword = passwordUser(ctx, t, in.Driver, "pat@lakeside.edu")

			_, req, err := signIn(ctx, in, lakeside("idp_unknown"), sessioninfo.ReasonLogin)

			mu.Lock()
			defer mu.Unlock()
			tt.check(t, in.Driver, err, req, passwordless, withPassword, provisioned)
		})
	}
}

func testLinkAcrossConnections(ctx context.Context, t *testing.T, h *AuthHarness) {
	var (
		user    *dbtype.SessionUser
		trusted bool
		mu      sync.Mutex
	)
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		mu.Lock()
		defer mu.Unlock()

		return signin.Link(user.ID, trusted), nil
	}})
	user = createUser(ctx, t, in.Driver, "cross@lakeside.edu")
	if _, err := in.Driver.LinkIdentity(ctx, user.ID, lakeside("idp_cross"), ""); err != nil {
		t.Fatalf("LinkIdentity() error = %v", err)
	}

	// An identity from another connection, untrusted: refused, nothing linked. The user
	// has no password, so nothing could confirm the link.
	_, _, err := signIn(ctx, in, riverside("idp_cross_other"), sessioninfo.ReasonLogin)
	assertRefused(t, err, sessioninfo.RefusedIdentityRejected, signin.ErrLinkCrossConnection)
	assertNoLink(ctx, t, in.Driver, riverside("idp_cross_other"))

	// A second identity on the connection the user already signs in through links: the
	// provider keeps its subjects unique.
	if _, req, err := signIn(ctx, in, lakeside("idp_cross_second"), sessioninfo.ReasonLogin); err != nil || req.UserID != user.ID {
		t.Errorf("same-connection sign-in = (%v, %v), want the user %v linked", req.UserID, err, user.ID)
	}

	// The other connection, trusted: the resolver vouches, so it links.
	mu.Lock()
	trusted = true
	mu.Unlock()
	if _, req, err := signIn(ctx, in, riverside("idp_cross_other"), sessioninfo.ReasonLogin); err != nil || req.UserID != user.ID {
		t.Errorf("trusted cross-connection sign-in = (%v, %v), want the user %v linked", req.UserID, err, user.ID)
	}

	// With links on two connections now, an untrusted identity on either of them still
	// links: the connection adds nothing the user does not sign in through already.
	mu.Lock()
	trusted = false
	mu.Unlock()
	if _, req, err := signIn(ctx, in, lakeside("idp_cross_third"), sessioninfo.ReasonLogin); err != nil || req.UserID != user.ID {
		t.Errorf("same-connection sign-in with two connections linked = (%v, %v), want the user %v linked", req.UserID, err, user.ID)
	}

	links, err := in.Driver.IdentitiesByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("IdentitiesByUser() error = %v", err)
	}
	if len(links) != 4 {
		t.Errorf("IdentitiesByUser() = %d links, want 4: the seeded one, two on the same connection and the trusted one", len(links))
	}
}

func testConcurrentCrossConnectionLinks(ctx context.Context, t *testing.T, h *AuthHarness) {
	// Each racing pair signs in with its own subject, which names the user it links.
	var (
		mu    sync.Mutex
		users = map[string]ccc.UUID{}
	)
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Resolve: func(_ context.Context, _ HookTx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		// Hold the sign-ins together, so their link decisions race.
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()

		return signin.Link(users[req.Identity.Subject], false), nil
	}})

	const n = 6
	subjects := make([]string, n)
	for i := range n {
		subjects[i] = fmt.Sprintf("idp_pair_%d", i)
		user := createUser(ctx, t, in.Driver, subjects[i]+"@lakeside.edu")
		mu.Lock()
		users[subjects[i]] = user.ID
		mu.Unlock()
	}

	var wg sync.WaitGroup
	errs := make([][2]error, n)
	for i := range n {
		for j, identity := range []*sessioninfo.Identity{lakeside(subjects[i]), riverside(subjects[i])} {
			wg.Go(func() {
				_, _, errs[i][j] = signIn(ctx, in, identity, sessioninfo.ReasonLogin)
			})
		}
	}
	wg.Wait()

	for i, pair := range errs {
		linked := 0
		for _, err := range pair {
			if err == nil {
				linked++

				continue
			}
			assertRefused(t, err, sessioninfo.RefusedIdentityRejected, signin.ErrLinkCrossConnection)
		}
		if linked != 1 {
			t.Errorf("pair %d: %d sign-ins linked, want exactly one of the two connections", i, linked)
		}
		links, err := in.Driver.IdentitiesByUser(ctx, users[subjects[i]])
		if err != nil {
			t.Fatalf("IdentitiesByUser() error = %v", err)
		}
		if len(links) != 1 {
			t.Errorf("pair %d: IdentitiesByUser() = %d links, want 1", i, len(links))
		}
	}
}

func testSignInPolicy(_ context.Context, t *testing.T, h *AuthHarness) {
	tests := []struct {
		name     string
		decision *signin.Decision
		reason   sessioninfo.NewSessionReason
		password bool
		// provision makes the identity unlinked and provisioned by the resolver.
		provision bool
		check     func(t *testing.T, d AuthDriver, err error, user *dbtype.SessionUser)
	}{
		{
			name:     "AllowSignIn signs in",
			decision: signin.Allow(),
			reason:   sessioninfo.ReasonLogin,
			check: func(t *testing.T, _ AuthDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				if err != nil {
					t.Errorf("sign-in error = %v, want allowed", err)
				}
			},
		},
		{
			name:     "DenySignIn refuses with the policy's code",
			decision: signin.Deny("sso_required"),
			reason:   sessioninfo.ReasonLogin,
			check: func(t *testing.T, _ AuthDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, "sso_required", signin.ErrSignInDenied)
			},
		},
		{
			name:   "no decision denies with the default code",
			reason: sessioninfo.ReasonLogin,
			check: func(t *testing.T, _ AuthDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedByPolicy, signin.ErrSignInDenied)
			},
		},
		{
			name:     "the policy decides a password sign-in too",
			decision: signin.Deny(""),
			reason:   sessioninfo.ReasonLogin,
			password: true,
			check: func(t *testing.T, _ AuthDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedByPolicy, signin.ErrSignInDenied)
			},
		},
		{
			name:     "RequireMFA reports the pending MFA for the user, with the factors the policy accepts",
			decision: signin.RequireMFA("email-otp", "totp"),
			reason:   sessioninfo.ReasonLogin,
			check: func(t *testing.T, _ AuthDriver, err error, user *dbtype.SessionUser) {
				t.Helper()
				var pending *signin.PendingSignInError
				if !errors.As(err, &pending) {
					t.Fatalf("sign-in error = %v, want a PendingSignInError", err)
				}
				want := signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(user.ID), Username: user.Username, Factors: []sessioninfo.AuthMethod{"email-otp", "totp"}}
				if diff := cmp.Diff(want, *pending, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("PendingSignInError mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name:      "a denied provisioning sign-in keeps the user and its link: the resolver's decision stands",
			decision:  signin.Deny(""),
			reason:    sessioninfo.ReasonLogin,
			provision: true,
			check: func(t *testing.T, d AuthDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedByPolicy, signin.ErrSignInDenied)
				user, uerr := d.UserByUserName(t.Context(), "fresh@lakeside.edu")
				if uerr != nil {
					t.Fatalf("UserByUserName() error = %v, want the provisioned user", uerr)
				}
				if link, lerr := d.Identity(t.Context(), sessioninfo.MethodWorkOS, "conn_lakeside", "idp_fresh"); lerr != nil || link.UserID != user.ID {
					t.Errorf("Identity() = %+v, %v; want the link to the provisioned user %v", link, lerr, user.ID)
				}
			},
		},
		{
			name:      "an MFA wait on a provisioning sign-in names the user it provisioned, so the application can send its code",
			decision:  signin.RequireMFA(),
			reason:    sessioninfo.ReasonLogin,
			provision: true,
			check: func(t *testing.T, d AuthDriver, err error, _ *dbtype.SessionUser) {
				t.Helper()
				var pending *signin.PendingSignInError
				if !errors.As(err, &pending) || pending.Reason != sessioninfo.PendingMFA {
					t.Fatalf("sign-in error = %v, want a PendingSignInError for MFA", err)
				}
				user, uerr := d.UserByUserName(t.Context(), "fresh@lakeside.edu")
				if uerr != nil {
					t.Fatalf("UserByUserName() error = %v, want the provisioned user", uerr)
				}
				want := signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(user.ID), Username: user.Username}
				if diff := cmp.Diff(want, *pending, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("PendingSignInError mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name:     "a step-up completion is not decided again",
			decision: signin.RequireMFA(),
			reason:   sessioninfo.ReasonStepUp,
			check: func(t *testing.T, _ AuthDriver, err error, _ *dbtype.SessionUser) {
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

			in := h.New(ctx, t, Auth, AuthConfig{
				Auth: true,
				Resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
					return signin.Provision(&signin.NewUser{Username: "fresh@lakeside.edu"}, nil), nil
				},
				Policy: func(_ context.Context, _ HookTx, req *sessioninfo.NewSessionRequest) (*signin.Decision, error) {
					if req.UserID.IsNil() {
						return nil, errors.New("the policy ran before the user was known")
					}

					return tt.decision, nil
				},
			})
			user := createUser(ctx, t, in.Driver, "jane@lakeside.edu")

			var err error
			switch {
			case tt.provision:
				_, _, err = signIn(ctx, in, lakeside("idp_fresh"), tt.reason)
			case tt.password:
				_, err = passwordSignIn(ctx, in, user, tt.reason)
			default:
				mustLink(ctx, t, in.Driver, user.ID, lakeside("idp_jane"))
				_, _, err = signIn(ctx, in, lakeside("idp_jane"), tt.reason)
			}

			tt.check(t, in.Driver, err, user)
		})
	}
}

func testDisabledUserRefused(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "gone@lakeside.edu")
	mustLink(ctx, t, in.Driver, user.ID, lakeside("idp_gone"))
	if err := in.Driver.DeactivateUser(ctx, user.ID); err != nil {
		t.Fatalf("DeactivateUser() error = %v", err)
	}

	_, _, err := signIn(ctx, in, lakeside("idp_gone"), sessioninfo.ReasonLogin)

	assertRefused(t, err, sessioninfo.RefusedUserDisabled, signin.ErrUserDisabled)
}

func testProvisionUsernameTaken(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		return signin.Provision(&signin.NewUser{Username: "taken@lakeside.edu"}, nil), nil
	}})
	createUser(ctx, t, in.Driver, "taken@lakeside.edu")

	_, _, err := signIn(ctx, in, lakeside("idp_dup"), sessioninfo.ReasonLogin)

	if !httpio.HasConflict(err) {
		t.Errorf("sign-in error = %v, want Conflict for the taken username", err)
	}
	assertNoLink(ctx, t, in.Driver, lakeside("idp_dup"))
}

func testConcurrentFirstSignIn(ctx context.Context, t *testing.T, h *AuthHarness) {
	var user *dbtype.SessionUser
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		// Hold the window between the lookup and the link open, so the sign-ins race.
		time.Sleep(100 * time.Millisecond)

		return signin.Link(user.ID, false), nil
	}})
	user = createUser(ctx, t, in.Driver, "race@lakeside.edu")

	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			_, req, err := signIn(ctx, in, lakeside("idp_race"), sessioninfo.ReasonLogin)
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

func testConcurrentFirstProvision(ctx context.Context, t *testing.T, h *AuthHarness) {
	const username = "provisioned-race@lakeside.edu"
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		// Hold the window between the lookup and the insert open, so the sign-ins race.
		time.Sleep(100 * time.Millisecond)

		return signin.Provision(&signin.NewUser{Username: username}, nil), nil
	}})

	const n = 4
	var wg sync.WaitGroup
	ids := make([]ccc.UUID, n)
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			_, req, err := signIn(ctx, in, lakeside("idp_provision_race"), sessioninfo.ReasonLogin)
			if err == nil {
				ids[i] = req.UserID
			}
			errs[i] = err
		})
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("sign-in %d error = %v, want every racing sign-in to succeed: the loser finds the winner's link", i, err)
		}
	}
	user, err := in.Driver.UserByUserName(ctx, username)
	if err != nil {
		t.Fatalf("UserByUserName() error = %v", err)
	}
	for i, id := range ids {
		if errs[i] == nil && id != user.ID {
			t.Errorf("sign-in %d signed in to %v, want the one provisioned user %v", i, id, user.ID)
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

func testLinkManagement(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
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
		t.Errorf("UnlinkIdentity() of a password-less user's only identity error = %v, want ErrLastSignInMethod (Conflict)", err)
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
		t.Errorf("UnlinkIdentity() of a user that has a password error = %v, want removed", err)
	}
	if err := in.Driver.UnlinkIdentity(ctx, patLink.ID); !httpio.HasNotFound(err) {
		t.Errorf("UnlinkIdentity() of a removed link error = %v, want NotFound", err)
	}
}

func testDeleteUserDeletesLinks(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	sso := createUser(ctx, t, in.Driver, "gone@lakeside.edu")
	other := createUser(ctx, t, in.Driver, "stays@lakeside.edu")
	mustLink(ctx, t, in.Driver, sso.ID, lakeside("idp_gone"))
	mustLink(ctx, t, in.Driver, sso.ID, &sessioninfo.Identity{Method: sessioninfo.MethodAzure, Connection: "tenant-1", Subject: "oid-gone"})
	kept := mustLink(ctx, t, in.Driver, other.ID, lakeside("idp_stays"))

	if err := in.Driver.DeleteUser(ctx, sso.ID); err != nil {
		t.Fatalf("DeleteUser() of a linked user error = %v", err)
	}

	assertNoLink(ctx, t, in.Driver, lakeside("idp_gone"))
	if links, err := in.Driver.IdentitiesByUser(ctx, sso.ID); err != nil || len(links) != 0 {
		t.Errorf("IdentitiesByUser() of the deleted user = %v, %v; want none", links, err)
	}
	if link, err := in.Driver.Identity(ctx, sessioninfo.MethodWorkOS, "conn_lakeside", "idp_stays"); err != nil || link.ID != kept.ID {
		t.Errorf("Identity() of another user's link = %v, %v; want it kept", link, err)
	}
	if err := in.Driver.DeleteUser(ctx, sso.ID); !httpio.HasNotFound(err) {
		t.Errorf("DeleteUser() of a deleted user error = %v, want NotFound", err)
	}
}

func testDestroyUserSessions(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Impersonation: true})
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
		imp := dbtype.NewInsertImpersonation(&sessioninfo.Impersonation{Actor: actor, Principal: principal, ExpiresAt: time.Now().Add(time.Hour)})
		id, err := in.Driver.InsertImpersonatedSession(ctx, newInsertSession(username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: username, UserID: userID}, imp)
		if err != nil {
			t.Fatalf("InsertImpersonatedSession() error = %v", err)
		}

		return id
	}

	// A session row carrying jane's username but another user's ID (a rename in
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
		{"another user's session under jane's username", borrowedName, false},
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

func testAppendAuthEvent(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, AuthEvents: true})
	user := createUser(ctx, t, in.Driver, "jane@lakeside.edu")
	mustLink(ctx, t, in.Driver, user.ID, lakeside("idp_jane"))

	id, _, err := signIn(ctx, in, lakeside("idp_jane"), sessioninfo.ReasonLogin)
	if err != nil {
		t.Fatalf("sign-in error = %v", err)
	}

	signedIn := mustSession(ctx, t, in.Driver, id)

	// A step-up with a time (a past one: the database refuses a future one) is recorded
	// at that time, which becomes the session's authentication time.
	stepUp := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	if err := in.Driver.AppendAuthEvent(ctx, id, &sessioninfo.AuthEvent{Method: "email-otp", At: stepUp}); err != nil {
		t.Fatalf("AppendAuthEvent() error = %v", err)
	}
	sess := mustSession(ctx, t, in.Driver, id)
	want := []sessioninfo.AuthEvent{
		{Method: sessioninfo.MethodWorkOS, Connection: "conn_lakeside", IDPAMR: []string{"mfa"}, At: signedIn.CreatedAt},
		{Method: "email-otp", At: stepUp},
	}
	if diff := cmp.Diff(want, sess.AuthEvents, eventsOpts); diff != "" {
		t.Errorf("Session().AuthEvents mismatch (-want +got):\n%s", diff)
	}
	if sess.AuthenticatedAt == nil || !sess.AuthenticatedAt.Equal(stepUp) {
		t.Errorf("Session().AuthenticatedAt = %v, want the step-up time %v", sess.AuthenticatedAt, stepUp)
	}

	// A step-up without a time is recorded at the database's, and so is the session.
	w := startWindow(h.ClockLead)
	if err := in.Driver.AppendAuthEvent(ctx, id, &sessioninfo.AuthEvent{Method: "totp"}); err != nil {
		t.Fatalf("AppendAuthEvent() without a time error = %v", err)
	}
	w.done()
	sess = mustSession(ctx, t, in.Driver, id)
	if len(sess.AuthEvents) != 3 || sess.AuthEvents[2].Method != "totp" {
		t.Fatalf("Session().AuthEvents = %v, want the step-up appended third", sess.AuthEvents)
	}
	w.assertStamped(t, "Session().AuthEvents[2].At", sess.AuthEvents[2].At)
	if sess.AuthenticatedAt == nil {
		t.Fatal("Session().AuthenticatedAt = nil, want the step-up's time")
	}
	assertSameTime(t, "Session().AuthenticatedAt", *sess.AuthenticatedAt, sess.AuthEvents[2].At)

	h.DeleteSession(ctx, t, in.Raw, id)
	if err := in.Driver.AppendAuthEvent(ctx, id, &sessioninfo.AuthEvent{Method: "email-otp"}); !httpio.HasNotFound(err) {
		t.Errorf("AppendAuthEvent() on a missing session error = %v, want NotFound", err)
	}
}
