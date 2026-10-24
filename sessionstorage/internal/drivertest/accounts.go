package drivertest

import (
	"context"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// entra is an external identity of the Entra tenant tenant-1 that signs in under
// signInName, as the Entra method reports a member: the sign-in name is the user
// principal name.
func entra(subject, signInName string) *sessioninfo.Identity {
	return &sessioninfo.Identity{
		Method: sessioninfo.MethodAzure, Connection: "tenant-1", Subject: subject, Email: signInName, SignInName: signInName,
	}
}

// google is an external identity of the Google Workspace the registration names
// lakeside that signs in under email, as the Google method reports a member: the
// sign-in name is the address Google verified, and the Workspace is the organization.
func google(subject, email string) *sessioninfo.Identity {
	return &sessioninfo.Identity{
		Method: sessioninfo.MethodGoogle, Connection: "lakeside", Subject: subject, Email: email, EmailVerified: true, SignInName: email, Organization: "lakeside",
	}
}

// addressHolderName is the username of the user addressHolder creates: a name of the
// application's choosing, not the address.
const addressHolderName = "pat"

// addressHolder creates a user named addressHolderName who holds email, verified when
// verified says so, with a password when withPassword says so.
func addressHolder(ctx context.Context, t *testing.T, d AuthDriver, email string, verified, withPassword bool) *dbtype.SessionUser {
	t.Helper()

	insert := &dbtype.InsertSessionUser{Username: addressHolderName, Email: &email, EmailVerified: verified}
	if withPassword {
		hash, err := securehash.New(securehash.Argon2()).Hash("password")
		if err != nil {
			t.Fatal(err)
		}
		insert.PasswordHash = hash
	}
	user, err := d.CreateUser(ctx, insert, nil)
	if err != nil {
		t.Fatalf("CreateUser(%q) error = %v", addressHolderName, err)
	}

	return user
}

// organizationOf is identity with the organization the method names, as the Entra
// method names a tenant or the Google method a Workspace.
func organizationOf(identity *sessioninfo.Identity, organization string) *sessioninfo.Identity {
	identity.Organization = organization

	return identity
}

// signInRequest establishes a session for req through the instance's sign-in flow.
func signInRequest(ctx context.Context, in *AuthInstance, req *sessioninfo.NewSessionRequest) error {
	if _, err := in.SignIn(ctx, newInsertSession(req.Username), req); err != nil {
		return errors.Wrap(err, "AuthInstance.SignIn()")
	}

	return nil
}

// assertProvisioned fails unless the sign-in provisioned a password-less user under
// identity's sign-in name and linked identity to it with tenant.
func assertProvisioned(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, identity *sessioninfo.Identity, tenant string) {
	t.Helper()

	if err != nil {
		t.Fatalf("sign-in error = %v, want provisioned", err)
	}
	username := identity.SignInName
	user, err := d.UserByUserName(ctx, username)
	if err != nil {
		t.Fatalf("UserByUserName(%q) error = %v, want the provisioned user", username, err)
	}
	if req.UserID != user.ID || req.Username != username || !req.User.Provisioned() {
		t.Errorf("req = user %v %q (%+v), want the provisioned user %v %q", req.UserID, req.Username, req.User, user.ID, username)
	}
	if user.PasswordHash != nil {
		t.Error("the provisioned user has a password, want none")
	}
	assertLinkedTo(ctx, t, d, identity, user.ID, tenant)
}

// assertNewlyLinked fails unless the sign-in linked identity to the pre-created user
// with tenant, and signed in as that user under its stored username.
func assertNewlyLinked(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, identity *sessioninfo.Identity, user *dbtype.SessionUser, tenant string) {
	t.Helper()

	if err != nil {
		t.Fatalf("sign-in error = %v, want linked", err)
	}
	if req.UserID != user.ID || req.Username != user.Username || req.User.Source != sessioninfo.UserNewLink {
		t.Errorf("req = user %v %q (%+v), want the pre-created user %v %q, newly linked", req.UserID, req.Username, req.User, user.ID, user.Username)
	}
	assertLinkedTo(ctx, t, d, identity, user.ID, tenant)
}

// assertConfirmationPending fails unless the sign-in waits for user's password with
// tenant on the link to be made, and identity stays unlinked.
func assertConfirmationPending(ctx context.Context, t *testing.T, d AuthDriver, err error, identity *sessioninfo.Identity, user *dbtype.SessionUser, tenant string) {
	t.Helper()

	var pending *signin.PendingSignInError
	if !errors.As(err, &pending) {
		t.Fatalf("sign-in error = %v, want a PendingSignInError", err)
	}
	want := &signin.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(user.ID), Username: user.Username, Tenant: tenant}
	if pending.Reason != want.Reason || pending.UserID != want.UserID || pending.Username != want.Username || pending.Tenant != want.Tenant {
		t.Errorf("PendingSignInError = %+v, want %+v", pending, want)
	}
	assertNoLink(ctx, t, d, identity)
}

// assertLinkedTo fails unless identity is linked to userID with tenant.
func assertLinkedTo(ctx context.Context, t *testing.T, d AuthDriver, identity *sessioninfo.Identity, userID ccc.UUID, tenant string) {
	t.Helper()

	link, err := d.Identity(ctx, identity.Method, identity.Connection, identity.Subject)
	if err != nil {
		t.Fatalf("Identity() error = %v, want the link", err)
	}
	if link.UserID != userID {
		t.Errorf("Identity().UserID = %v, want %v", link.UserID, userID)
	}
	if link.Tenant == nil || *link.Tenant != tenant {
		t.Errorf("Identity().Tenant = %v, want %q", link.Tenant, tenant)
	}
}

// assertNoUser fails when a user exists under username.
func assertNoUser(ctx context.Context, t *testing.T, d AuthDriver, username string) {
	t.Helper()

	if _, err := d.UserByUserName(ctx, username); !httpio.HasNotFound(err) {
		t.Errorf("UserByUserName(%q) error = %v, want NotFound: no user may be written", username, err)
	}
}

func testStandardAccountRules(_ context.Context, t *testing.T, h *AuthHarness) {
	const name = "pat.lee@lakeside.edu"

	tests := []struct {
		name     string
		accounts signin.StandardAccountRule
		// seed prepares the users before the sign-in and returns the one the identity
		// should reach, nil for none.
		seed func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser
		// identity signs in; nil is entra("oid-pat", name).
		identity *sessioninfo.Identity
		// roleNames are the role names the method asserted; nil for no role sync.
		roleNames []string
		check     func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser)
	}{
		{
			name:     "members of the directory: a stranger is provisioned under the sign-in name, with the connection as the tenant key",
			accounts: signin.MembersOfDirectory,
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, _ *dbtype.SessionUser) {
				assertProvisioned(ctx, t, d, err, req, entra("oid-pat", name), "tenant-1")
			},
		},
		{
			name:     "members of the directory: the organization the method names is the tenant key when it names one",
			accounts: signin.MembersOfDirectory,
			identity: organizationOf(entra("oid-pat", name), "lakeside"),
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, _ *dbtype.SessionUser) {
				assertProvisioned(ctx, t, d, err, req, organizationOf(entra("oid-pat", name), "lakeside"), "lakeside")
			},
		},
		{
			name:     "members of the directory: a pre-created user with a password must confirm with it",
			accounts: signin.MembersOfDirectory,
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				return passwordUser(ctx, t, d, name)
			},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				assertConfirmationPending(ctx, t, d, err, entra("oid-pat", name), seeded, "tenant-1")
			},
		},
		{
			name:     "members of the directory: a pre-created user without a password and no identity is linked outright",
			accounts: signin.MembersOfDirectory,
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				return createUser(ctx, t, d, name)
			},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				assertNewlyLinked(ctx, t, d, err, req, entra("oid-pat", name), seeded, "tenant-1")
			},
		},
		{
			name:     "members of the directory: the pre-created user is matched without regard to case, and keeps its spelling",
			accounts: signin.MembersOfDirectory,
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				return createUser(ctx, t, d, "Pat.Lee@Lakeside.edu")
			},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				assertNewlyLinked(ctx, t, d, err, req, entra("oid-pat", name), seeded, "tenant-1")
			},
		},
		{
			name:     "members of the directory: a pre-created password-less user who signs in through another connection is refused, as any untrusted link is",
			accounts: signin.MembersOfDirectory,
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				user := createUser(ctx, t, d, name)
				mustLink(ctx, t, d, user.ID, lakeside("idp_pat"))

				return user
			},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedIdentityRejected, signin.ErrLinkCrossConnection)
				assertNoLink(ctx, t, d, entra("oid-pat", name))
			},
		},
		{
			name:     "every standard rule: a guest of the directory is refused and nothing is written",
			accounts: signin.MembersOfDirectory,
			identity: func() *sessioninfo.Identity {
				guest := entra("oid-guest", "visitor_gmail.com#EXT#@lakeside.onmicrosoft.com")
				guest.Guest = true

				return guest
			}(),
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedGuestAccount, signin.ErrGuestAccount)
				assertNoUser(ctx, t, d, "visitor_gmail.com#EXT#@lakeside.onmicrosoft.com")
			},
		},
		{
			name:      "every standard rule: a token asserting no application role is refused before any row is written",
			accounts:  signin.MembersOfDirectory,
			roleNames: []string{},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedNoRoles, signin.ErrNoRoles)
				assertNoUser(ctx, t, d, name)
				assertNoLink(ctx, t, d, entra("oid-pat", name))
			},
		},
		{
			name:      "every standard rule: a token asserting a role goes on to the rule",
			accounts:  signin.MembersOfDirectory,
			roleNames: []string{"Editor"},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, _ *dbtype.SessionUser) {
				assertProvisioned(ctx, t, d, err, req, entra("oid-pat", name), "tenant-1")
			},
		},
		{
			name:     "every standard rule: an identity without a sign-in name is refused",
			accounts: signin.MembersOfDirectory,
			identity: entra("oid-nameless", ""),
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedNoEmail, signin.ErrNoSignInName)
				assertNoLink(ctx, t, d, entra("oid-nameless", ""))
			},
		},
		{
			name:     "invited users only: a pre-created user is linked",
			accounts: signin.InvitedUsersOnly,
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				return createUser(ctx, t, d, name)
			},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				assertNewlyLinked(ctx, t, d, err, req, entra("oid-pat", name), seeded, "tenant-1")
			},
		},
		{
			name:     "invited users only: a pre-created user with a password must confirm with it",
			accounts: signin.InvitedUsersOnly,
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				return passwordUser(ctx, t, d, name)
			},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				assertConfirmationPending(ctx, t, d, err, entra("oid-pat", name), seeded, "tenant-1")
			},
		},
		{
			name:     "invited users only: a stranger is refused and nothing is written",
			accounts: signin.InvitedUsersOnly,
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedNotInvited, signin.ErrNotInvited)
				assertNoUser(ctx, t, d, name)
				assertNoLink(ctx, t, d, entra("oid-pat", name))
			},
		},
		{
			name:     "open sign-up: a stranger is provisioned",
			accounts: signin.OpenSignUp,
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest, _ *dbtype.SessionUser) {
				assertProvisioned(ctx, t, d, err, req, entra("oid-pat", name), "tenant-1")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Accounts: tt.accounts})
			var seeded *dbtype.SessionUser
			if tt.seed != nil {
				seeded = tt.seed(ctx, t, in.Driver)
			}
			identity := tt.identity
			if identity == nil {
				identity = entra("oid-pat", name)
			}
			req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: identity.SignInName, Identity: identity, RoleNames: tt.roleNames}

			err := signInRequest(ctx, in, req)

			tt.check(ctx, t, in.Driver, err, req, seeded)
		})
	}
}

func testResolveByVerifiedAddress(_ context.Context, t *testing.T, h *AuthHarness) {
	const address = "pat.lee@lakeside.edu"
	// The person's Google account, whose verified address is the sign-in name; the
	// user the application created for the person (addressHolder) is named pat, not
	// the address.
	identity := func() *sessioninfo.Identity { return google("sub-pat", address) }

	tests := []struct {
		name string
		// seed prepares the users before the sign-in and returns the one holding the
		// address.
		seed func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser
		// identity signs in; nil is the Google identity.
		identity *sessioninfo.Identity
		check    func(ctx context.Context, t *testing.T, in *AuthInstance, err error, req *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser)
	}{
		{
			name: "a user who holds the address verified and has a password must confirm with it; the confirmation links the identity to that user, and no second user is made",
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				return addressHolder(ctx, t, d, address, true, true)
			},
			check: func(ctx context.Context, t *testing.T, in *AuthInstance, err error, _ *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				t.Helper()
				assertConfirmationPending(ctx, t, in.Driver, err, identity(), seeded, "lakeside")
				assertNoUser(ctx, t, in.Driver, address)

				// The confirmation links the identity to the user it waited on, as the
				// Auth does, and the next sign-in is by the link.
				if _, err := in.Driver.LinkIdentity(ctx, seeded.ID, identity(), "lakeside"); err != nil {
					t.Fatalf("LinkIdentity() error = %v", err)
				}
				again := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: address, Identity: identity()}
				if err := signInRequest(ctx, in, again); err != nil {
					t.Fatalf("sign-in after the confirmation error = %v", err)
				}
				if again.UserID != seeded.ID || again.Username != addressHolderName || again.User.Source != sessioninfo.UserExistingLink {
					t.Errorf("sign-in after the confirmation = user %v %q (%+v), want the linked user %v %q", again.UserID, again.Username, again.User, seeded.ID, addressHolderName)
				}
				assertNoUser(ctx, t, in.Driver, address)
			},
		},
		{
			name: "a user who holds the address verified, without a password and with no identity, is linked",
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				return addressHolder(ctx, t, d, address, true, false)
			},
			check: func(ctx context.Context, t *testing.T, in *AuthInstance, err error, req *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				t.Helper()
				assertNewlyLinked(ctx, t, in.Driver, err, req, identity(), seeded, "lakeside")
				assertNoUser(ctx, t, in.Driver, address)
			},
		},
		{
			name: "the address is matched without regard to case",
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				return addressHolder(ctx, t, d, "Pat.Lee@Lakeside.edu", true, false)
			},
			check: func(ctx context.Context, t *testing.T, in *AuthInstance, err error, req *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				assertNewlyLinked(ctx, t, in.Driver, err, req, identity(), seeded, "lakeside")
			},
		},
		{
			name: "a password-less user who holds the address verified and signs in through another connection is refused, as any untrusted link is",
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				user := addressHolder(ctx, t, d, address, true, false)
				mustLink(ctx, t, d, user.ID, lakeside("idp_pat"))

				return user
			},
			check: func(ctx context.Context, t *testing.T, in *AuthInstance, err error, _ *sessioninfo.NewSessionRequest, _ *dbtype.SessionUser) {
				t.Helper()
				assertRefused(t, err, sessioninfo.RefusedIdentityRejected, signin.ErrLinkCrossConnection)
				assertNoLink(ctx, t, in.Driver, identity())
				assertNoUser(ctx, t, in.Driver, address)
			},
		},
		{
			name: "a password-less user who holds the address verified and signs in through the same connection is linked",
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				user := addressHolder(ctx, t, d, address, true, false)
				mustLink(ctx, t, d, user.ID, google("sub-pat-old", "old@lakeside.edu"))

				return user
			},
			check: func(ctx context.Context, t *testing.T, in *AuthInstance, err error, req *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				assertNewlyLinked(ctx, t, in.Driver, err, req, identity(), seeded, "lakeside")
			},
		},
		{
			name: "an address a user holds unverified matches no one: the person is provisioned as a stranger, without an address, and the entry stays with its user",
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				return addressHolder(ctx, t, d, address, false, false)
			},
			check: func(ctx context.Context, t *testing.T, in *AuthInstance, err error, req *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				t.Helper()
				assertProvisioned(ctx, t, in.Driver, err, req, identity(), "lakeside")
				assertEmail(t, "User() of the provisioned user", mustUser(ctx, t, in.Driver, req.UserID), nil, false)
				assertEmail(t, "User() of the holder", mustUser(ctx, t, in.Driver, seeded.ID), strPtr(address), false)
			},
		},
		{
			name:     "an address the method did not verify matches no one: the person is provisioned under the sign-in name, and the holder keeps the address",
			identity: entra("oid-pat", address),
			seed: func(ctx context.Context, t *testing.T, d AuthDriver) *dbtype.SessionUser {
				return addressHolder(ctx, t, d, address, true, false)
			},
			check: func(ctx context.Context, t *testing.T, in *AuthInstance, err error, req *sessioninfo.NewSessionRequest, seeded *dbtype.SessionUser) {
				t.Helper()
				assertProvisioned(ctx, t, in.Driver, err, req, entra("oid-pat", address), "tenant-1")
				assertEmail(t, "User() of the provisioned user", mustUser(ctx, t, in.Driver, req.UserID), nil, false)
				assertEmail(t, "User() of the holder", mustUser(ctx, t, in.Driver, seeded.ID), strPtr(address), true)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Accounts: signin.MembersOfDirectory})
			seeded := tt.seed(ctx, t, in.Driver)
			id := tt.identity
			if id == nil {
				id = identity()
			}
			req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: id.SignInName, Identity: id}

			err := signInRequest(ctx, in, req)

			tt.check(ctx, t, in, err, req, seeded)
		})
	}

	// A registration's own rule may provision a user of its own choosing; the address
	// another user holds verified decides the same way.
	provisionChosen := func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		return signin.Provision(&signin.NewUser{Username: "chosen"}, nil, signin.Tenant("lakeside")), nil
	}

	t.Run("a rule that provisions a new user for an identity whose verified address another user holds verified is refused, and nothing is written", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Resolve: provisionChosen})
		addressHolder(ctx, t, in.Driver, address, true, false)

		err := signInRequest(ctx, in, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: address, Identity: identity()})

		assertRefused(t, err, sessioninfo.RefusedIdentityRejected, signin.ErrEmailHeld)
		assertNoUser(ctx, t, in.Driver, "chosen")
		assertNoLink(ctx, t, in.Driver, identity())
	})

	t.Run("a rule that provisions a new user for an identity whose verified address a user holds unverified provisions it: the entry reserves nothing against a sign-in", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Resolve: provisionChosen})
		seeded := addressHolder(ctx, t, in.Driver, address, false, false)
		req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: address, Identity: identity()}

		err := signInRequest(ctx, in, req)

		if err != nil || req.Username != "chosen" || !req.User.Provisioned() {
			t.Fatalf("sign-in = %v, user %q (%+v); want the rule's user provisioned", err, req.Username, req.User)
		}
		assertLinkedTo(ctx, t, in.Driver, identity(), req.UserID, "lakeside")
		assertEmail(t, "User() of the provisioned user", mustUser(ctx, t, in.Driver, req.UserID), nil, false)
		assertEmail(t, "User() of the holder", mustUser(ctx, t, in.Driver, seeded.ID), strPtr(address), false)
	})
}

func testCustomRuleBeforeStandardRule(_ context.Context, t *testing.T, h *AuthHarness) {
	const name = "pat.lee@lakeside.edu"

	tests := []struct {
		name string
		// resolve is the custom rule; the standard rule is members of the directory.
		resolve func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error)
		check   func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest)
	}{
		{
			name: "Standard leaves the identity to the standard rule, with the connection as the tenant key",
			resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
				return signin.Standard(), nil
			},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest) {
				assertProvisioned(ctx, t, d, err, req, entra("oid-pat", name), "tenant-1")
			},
		},
		{
			name: "Standard with a tenant key stores that key",
			resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
				return signin.Standard(signin.Tenant("partner-9")), nil
			},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest) {
				assertProvisioned(ctx, t, d, err, req, entra("oid-pat", name), "partner-9")
				if req.User != nil && req.User.Tenant != "partner-9" {
					t.Errorf("req.User.Tenant = %q, want the custom rule's key", req.User.Tenant)
				}
			},
		},
		{
			name: "a refusal by the custom rule is final: the standard rule is not consulted",
			resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
				return signin.Reject("not_a_partner"), nil
			},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, _ *sessioninfo.NewSessionRequest) {
				t.Helper()
				assertRefused(t, err, "not_a_partner", signin.ErrIdentityRejected)
				assertNoUser(ctx, t, d, name)
			},
		},
		{
			name: "a decision by the custom rule stands on its own",
			resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
				return signin.Provision(&signin.NewUser{Username: "chosen@lakeside.edu"}, nil), nil
			},
			check: func(ctx context.Context, t *testing.T, d AuthDriver, err error, req *sessioninfo.NewSessionRequest) {
				t.Helper()
				if err != nil || req.Username != "chosen@lakeside.edu" {
					t.Fatalf("sign-in error = %v, username %q; want the custom rule's user", err, req.Username)
				}
				assertNoUser(ctx, t, d, name)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Accounts: signin.MembersOfDirectory, Resolve: tt.resolve})
			identity := entra("oid-pat", name)
			req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: name, Identity: identity}

			err := signInRequest(ctx, in, req)

			tt.check(ctx, t, in.Driver, err, req)
		})
	}

	t.Run("a custom rule answering Standard on a method without a standard rule fails the sign-in, writing nothing", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()

		in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Resolve: func(context.Context, HookTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
			return signin.Standard(), nil
		}})

		_, _, err := signIn(ctx, in, lakeside("idp_pat"), sessioninfo.ReasonLogin)

		var refusal *sessioninfo.LoginRefusal
		if err == nil || errors.As(err, &refusal) {
			t.Errorf("sign-in error = %v, want a failure that is not a refusal", err)
		}
		assertNoLink(ctx, t, in.Driver, lakeside("idp_pat"))
	})
}

func testStandardRuleRunsOnce(ctx context.Context, t *testing.T, h *AuthHarness) {
	const name = "pat.lee@lakeside.edu"
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Accounts: signin.InvitedUsersOnly})
	user := createUser(ctx, t, in.Driver, name)

	first := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: name, Identity: entra("oid-pat", name)}
	if err := signInRequest(ctx, in, first); err != nil {
		t.Fatalf("first sign-in error = %v", err)
	}
	// The directory renames the person: the link, not the name, finds the user, and
	// the username is not renamed.
	renamed := entra("oid-pat", "patricia.lee@lakeside.edu")
	second := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: renamed.SignInName, Identity: renamed}
	if err := signInRequest(ctx, in, second); err != nil {
		t.Fatalf("second sign-in error = %v, want the link to sign in without the rule", err)
	}

	if second.UserID != user.ID || second.User.Source != sessioninfo.UserExistingLink || second.Username != name {
		t.Errorf("second sign-in = user %v %q (%+v), want the linked user %v under %q", second.UserID, second.Username, second.User, user.ID, name)
	}
	assertNoUser(ctx, t, in.Driver, "patricia.lee@lakeside.edu")
}
