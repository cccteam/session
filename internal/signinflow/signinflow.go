// Package signinflow establishes the session of an Auth sign-in over a storage driver:
// it resolves the identity's user, decides the sign-in and inserts the session, once
// for every driver, generic over the driver's transaction type. The drivers keep the
// SQL: each supplies the primitives, every one taking the transaction the flow opened.
package signinflow

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// Driver is what the flow needs from a storage driver. Every primitive runs inside a
// transaction Transact opened and receives it.
type Driver[Tx any] interface {
	// Transact runs fn in a read-write transaction and commits when fn returns nil.
	// Spanner retries an aborted transaction, so fn may run more than once and starts
	// from its inputs on every run.
	Transact(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
	// IdentityIn returns the link for (method, connection, subject), or nil when the
	// identity is not linked.
	IdentityIn(ctx context.Context, tx Tx, method sessioninfo.AuthMethod, connection, subject string) (*dbtype.SessionIdentity, error)
	// TouchIdentityIn moves a link's LastUsedAt to the database's time at commit.
	TouchIdentityIn(ctx context.Context, tx Tx, linkID ccc.UUID) error
	// LinkIdentityIn writes a new link of identity to userID, created and last used at
	// the database's time at commit. A link of the same identity made meanwhile ends the
	// transaction with an IdentityConflict.
	LinkIdentityIn(ctx context.Context, tx Tx, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) error
	// IdentitiesByUserIn lists userID's links inside tx, oldest first.
	IdentitiesByUserIn(ctx context.Context, tx Tx, userID ccc.UUID) ([]*dbtype.SessionIdentity, error)
	// UserIn reads the part of userID's user the flow decides on. A missing user is
	// NotFound.
	UserIn(ctx context.Context, tx Tx, userID ccc.UUID) (*dbtype.User, error)
	// LockUserIn reads the user as UserIn does and holds the user against another link
	// decision until tx ends, so the check of the user's links and the new link are
	// not raced; a session insert for the user, and an account rule's own reads of the
	// user, are not held. A missing user is NotFound.
	LockUserIn(ctx context.Context, tx Tx, userID ccc.UUID) (*dbtype.User, error)
	// UserByUsernameIn reads the user whose username is username, matched without
	// regard to case as the users table's normalized username is, or nil when there is
	// none.
	UserByUsernameIn(ctx context.Context, tx Tx, username string) (*dbtype.User, error)
	// InsertUserIn writes a new user row and returns its ID. A taken username ends the
	// transaction with a UsernameConflict.
	InsertUserIn(ctx context.Context, tx Tx, user *dbtype.InsertSessionUser) (ccc.UUID, error)
	// InsertSessionIn writes session row id for req with its auth events and its custom
	// session data: req.CustomData, or what the configured resolver returns.
	InsertSessionIn(ctx context.Context, tx Tx, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) error
	// SignInConflict classifies the error a transaction ended with.
	SignInConflict(err error) dbtype.SignInConflict
	// ConsumeMailLinkIn consumes the live mail link id inside tx, at the database's
	// time at commit. A link that is not live is NotFound, and the transaction may go
	// on.
	ConsumeMailLinkIn(ctx context.Context, tx Tx, id ccc.UUID, now time.Time) error
	// ClaimVerifiedEmailIn writes email on the user as verified inside tx when the
	// user holds no verified address yet and no other user holds email, and reports
	// whether it wrote.
	ClaimVerifiedEmailIn(ctx context.Context, tx Tx, userID ccc.UUID, email string) (bool, error)
	// UserByEmailIn reads the user holding email inside tx, verified or not, matched
	// without regard to case, or nil when there is none.
	UserByEmailIn(ctx context.Context, tx Tx, email string) (*dbtype.User, error)
	// UsernameIsEmail reports whether the store's usernames are the addresses.
	UsernameIsEmail() bool
}

// InvitationAcceptor is the application's half of an invitation's acceptance: it
// grants what the invitation names (its roles, in its tenant) to userID, once the
// transaction that consumed the invitation has committed and before the sign-in
// policy runs, so the policy sees the membership. It runs outside any transaction,
// exactly once per acceptance: an application's memberships live in a store of their
// own, written through its own client, which no transaction of the session store can
// carry (and which the Spanner emulator, allowing one read-write transaction at a
// time, would deadlock inside one). A hook that fails ends the sign-in with its
// error; the invitation stays consumed and a user it provisioned stays, so the
// person's next attempt at the link finds it dead and an administrator invites again.
type InvitationAcceptor func(ctx context.Context, userID ccc.UUID, username string, inv *sessioninfo.Invitation) error

// Rules are the application's rules a sign-in runs under.
type Rules[Tx any] struct {
	// Account is the registration's own account rule, nil for none, and Standard the
	// registration's standard rule, "" for none; see SignIn.
	Account  signin.AccountRule[Tx]
	Standard signin.StandardAccountRule
	// Policy is the sign-in policy, nil for none.
	Policy signin.Policy[Tx]
	// Accept is the application's invitation acceptor, nil for none.
	Accept InvitationAcceptor
}

// SignIn establishes session id for a request that carries a verified identity, in two
// transactions (see the README's "Storage and schema"). The first resolves an external
// identity's user: a linked identity is its user's, and an unlinked one goes to the
// account rules: the registration's custom rule when it has one, and the standard rule
// when it has none or the custom rule answers signin.Standard. The second reads the
// user, asks policy and inserts the session. Each transaction commits unless a hook or
// the driver fails, so a refusal or a pending outcome keeps the hooks' own writes and
// writes no session. The resolution commits first because Spanner hides buffered
// writes from reads in the same transaction: the policy and the custom session data
// resolver must see a provisioned user and the rows OnProvisioned wrote.
//
// A password identity names its user in req.UserID and skips the resolution. Once the
// user is known, req.UserID, req.Username and req.User are set to it, whatever the
// outcome. A refusal is a *sessioninfo.LoginRefusal and a sign-in that must wait a
// *signin.PendingSignInError.
//
// A sign-in that carries an invitation (req.Invitation) accepts it once the user is
// known and before the policy decides, so the policy sees what the acceptance
// granted: the invitation is consumed and the user's address is set from it when the
// user holds no verified address, in the resolution transaction for an external
// identity (so a user the invitation provisioned and the consumption commit together)
// and in a transaction of its own for a password identity; once that has committed,
// rules.Accept grants what the invitation names, outside any transaction. An
// invitation that is no longer live is skipped and the sign-in goes on, unless the
// invitation alone admitted the person (the invited-users-only rule), which is then a
// refusal (invitation_expired) and provisions nothing; req.Invitation.Accepted reports
// whether it was accepted, which a failed grant leaves false.
func SignIn[Tx any](
	ctx context.Context, d Driver[Tx], id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest, rules Rules[Tx],
) error {
	if req.Identity == nil {
		return errors.New("a sign-in carries its verified identity in req.Identity")
	}

	resolved := *req
	resolved.User = nil
	defer func() { req.UserID, req.Username, req.User = resolved.UserID, resolved.Username, resolved.User }()

	source, tenant := sessioninfo.UserNamed, ""
	switch {
	case dbtype.IsExternal(req.Identity):
		if rules.Account == nil && rules.Standard == "" {
			return errors.Newf("the %s sign-in method has neither a standard account rule nor a custom one", req.Identity.Method)
		}
		var (
			stop error
			err  error
		)
		source, tenant, stop, err = resolveIdentity(ctx, d, &resolved, rules)
		if err != nil {
			return err
		}
		if stop != nil {
			return stop
		}
		// The resolution has committed, so a link or a provisioned user is reported
		// even when the decision then fails, and an invitation it consumed is granted
		// now, before the policy reads the memberships.
		resolved.User = &sessioninfo.SignInUser{ID: resolved.UserID, Username: resolved.Username, Source: source, Tenant: tenant}
		if err := grantConsumed(ctx, resolved.UserID, resolved.Username, req.Invitation, rules.Accept); err != nil {
			return err
		}
	case req.UserID.IsNil():
		return errors.New("a password sign-in names its user in req.UserID")
	default:
		if req.Invitation != nil {
			if err := AcceptInvitation(ctx, d, resolved.UserID, resolved.Username, req.Invitation, rules.Accept); err != nil && !httpio.HasNotFound(err) {
				return err
			}
		}
	}

	return decideAndInsert(ctx, d, id, insertSession, &resolved, source, tenant, rules.Policy)
}

// errInvitationDead ends the resolution transaction of a sign-in that its invitation
// alone admitted, once the invitation turns out to be dead: nothing is committed.
var errInvitationDead = errors.New("the invitation has expired or was already used")

// consumeInvitation consumes the invitation req carries, if any, inside the
// resolution's transaction, before the user is written, and reports whether it was
// live. A dead invitation is reported dead and the sign-in goes on without it, unless
// it alone admitted the person (byInvitation), which ends the transaction with
// errInvitationDead.
func consumeInvitation[Tx any](ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, byInvitation bool) (live bool, err error) {
	inv := req.Invitation
	if inv == nil {
		return false, nil
	}
	inv.Accepted = false
	if err := d.ConsumeMailLinkIn(ctx, tx, inv.ID, time.Now()); err != nil {
		if !httpio.HasNotFound(err) {
			return false, errors.Wrap(err, "Driver.ConsumeMailLinkIn()")
		}
		if byInvitation {
			return false, errInvitationDead
		}

		return false, nil
	}

	return true, nil
}

// claimInvitation finishes the consumption of the live invitation req carries for the
// user the resolution found, inside its transaction: the user's address is set from
// it when the user holds no verified address (a user provisioned in this transaction
// had it set at the insert). inv.Accepted marks the invitation as consumed for this
// user, so the grant follows once the transaction commits (grantConsumed).
func claimInvitation[Tx any](ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, source sessioninfo.UserSource) error {
	inv := req.Invitation
	if source != sessioninfo.UserProvisioned {
		if _, err := d.ClaimVerifiedEmailIn(ctx, tx, req.UserID, inv.Email); err != nil {
			return errors.Wrap(err, "Driver.ClaimVerifiedEmailIn()")
		}
	}
	inv.Accepted = true

	return nil
}

// grantConsumed runs the application's acceptor for an invitation the committed
// transaction consumed (inv.Accepted), outside any transaction. A failed grant ends
// the sign-in with the acceptor's error and leaves inv.Accepted false: the invitation
// is consumed and the user stays, so the next attempt at the link finds it dead.
func grantConsumed(ctx context.Context, userID ccc.UUID, username string, inv *sessioninfo.Invitation, accept InvitationAcceptor) error {
	if inv == nil || !inv.Accepted || accept == nil {
		return nil
	}
	if err := accept(ctx, userID, username, inv); err != nil {
		inv.Accepted = false

		return errors.Wrap(err, "InvitationAcceptor()")
	}

	return nil
}

// AcceptInvitation accepts inv for userID: in one transaction the invitation is
// consumed and the user's address is set from it when the user holds no verified
// address and no other user holds it; once that has committed, accept, nil for none,
// grants what the invitation names, outside any transaction. inv.Accepted is set to
// the outcome. An invitation that is no longer live (consumed, expired or revoked) is
// NotFound, and nothing is written; a grant that fails is the acceptor's error, with
// the invitation consumed.
func AcceptInvitation[Tx any](ctx context.Context, d Driver[Tx], userID ccc.UUID, username string, inv *sessioninfo.Invitation, accept InvitationAcceptor) error {
	inv.Accepted = false
	err := d.Transact(ctx, func(ctx context.Context, tx Tx) error {
		if err := d.ConsumeMailLinkIn(ctx, tx, inv.ID, time.Now()); err != nil {
			return errors.Wrap(err, "Driver.ConsumeMailLinkIn()")
		}
		if _, err := d.ClaimVerifiedEmailIn(ctx, tx, userID, inv.Email); err != nil {
			return errors.Wrap(err, "Driver.ClaimVerifiedEmailIn()")
		}

		return nil
	})
	if err != nil {
		if httpio.HasNotFound(err) {
			return httpio.NewNotFoundMessage("the invitation has expired or was already used")
		}

		return errors.Wrap(err, "Driver.Transact()")
	}
	inv.Accepted = true

	return grantConsumed(ctx, userID, username, inv, accept)
}

// resolveIdentity is the first transaction of SignIn. It sets req.UserID (and
// req.Username for a provisioned user) and reports how the user was found and the
// link's tenant. stop is a refusal or a pending confirmation; it still commits. When two
// first sign-ins of one identity race, the loser's link fails on the identities key (a
// provisioning loser on the username first), and its resolution runs once more and
// finds the winner's link. A transaction the database ends to break a deadlock or a
// serialization failure between racing sign-ins runs once more too.
func resolveIdentity[Tx any](
	ctx context.Context, d Driver[Tx], req *sessioninfo.NewSessionRequest, rules Rules[Tx],
) (source sessioninfo.UserSource, tenant string, stop, err error) {
	base := *req
	for attempt := 1; ; attempt++ {
		err = d.Transact(ctx, func(ctx context.Context, tx Tx) error {
			// Each run starts from the caller's request.
			*req = base
			var err error
			source, tenant, stop, err = resolveIn(ctx, d, tx, req, rules)

			return err
		})
		if err == nil {
			return source, tenant, stop, nil
		}
		if errors.Is(err, errInvitationDead) {
			return "", "", Refusal("", sessioninfo.RefusedInvitationExpired, signin.ErrInvitationExpired, "the invitation has expired or was already used"), nil
		}

		switch d.SignInConflict(err) {
		case dbtype.UsernameConflict:
			// A provisioning sign-in that loses a race for the same identity fails on
			// the username before it reaches the identities key: the winner's link is
			// there now, so the resolution runs once more and finds it. A username that
			// is simply taken is refused on the second run.
			if attempt == 1 {
				continue
			}

			return "", "", nil, httpio.NewConflictMessagef("username %q already exists", req.Username)
		case dbtype.IdentityConflict:
			if attempt == 1 {
				continue
			}
		case dbtype.LockConflict:
			// The database broke a deadlock (a rule that shared the user row's lock
			// before the link decision locked it) or a serialization failure between
			// racing sign-ins: the loser runs once more and sees what the winner wrote.
			if attempt == 1 {
				continue
			}
		case dbtype.NoSignInConflict:
		}

		return "", "", nil, errors.Wrap(err, "Driver.Transact()")
	}
}

// resolveIn is one run of the resolution inside tx. A linked identity resolves to its
// user and its LastUsedAt is touched. An unlinked one goes to the account rules, and
// their answer is applied. The invitation the sign-in carries is then consumed for
// the user found, in the same transaction; its grant follows the commit.
func resolveIn[Tx any](
	ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, rules Rules[Tx],
) (source sessioninfo.UserSource, tenant string, stop, err error) {
	link, err := d.IdentityIn(ctx, tx, req.Identity.Method, req.Identity.Connection, req.Identity.Subject)
	if err != nil {
		return "", "", nil, errors.Wrap(err, "Driver.IdentityIn()")
	}
	var live bool
	if link != nil {
		req.UserID = link.UserID
		if err := d.TouchIdentityIn(ctx, tx, link.ID); err != nil {
			return "", "", nil, errors.Wrap(err, "Driver.TouchIdentityIn()")
		}
		if link.Tenant != nil {
			tenant = *link.Tenant
		}
		source = sessioninfo.UserExistingLink
		if live, err = consumeInvitation(ctx, d, tx, req, false); err != nil {
			return "", "", nil, err
		}
	} else {
		res, byInvitation, stop, err := decideAccount(ctx, d, tx, req, rules.Account, rules.Standard)
		if err != nil || stop != nil {
			return "", "", stop, err
		}
		// The invitation is consumed before the user is written, so a dead one gives
		// a provisioned user nothing: not its address, not its grant.
		if live, err = consumeInvitation(ctx, d, tx, req, byInvitation); err != nil {
			return "", "", nil, err
		}
		source, tenant, stop, err = applyResolution(ctx, d, tx, req, res, live)
		if err != nil || stop != nil {
			return "", "", stop, err
		}
	}
	if live {
		if err := claimInvitation(ctx, d, tx, req, source); err != nil {
			return "", "", nil, err
		}
	}

	return source, tenant, nil, nil
}

// decideAccount asks the account rules what to do with an unlinked identity: the
// custom rule when the registration has one, and the standard rule when it has none or
// the custom rule answers signin.Standard. A refusal the standard rule makes before any
// row is written is returned as stop. The standard rule's tenant key is the
// organization the method names, or the identity's connection when it names none,
// unless the custom rule's Standard names another. byInvitation reports that the
// invitation the sign-in carries is what admitted the person.
func decideAccount[Tx any](
	ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, rule signin.AccountRule[Tx], standard signin.StandardAccountRule,
) (res *signin.Resolution, byInvitation bool, stop, err error) {
	tenant := req.Identity.Organization
	if tenant == "" {
		tenant = req.Identity.Connection
	}
	if rule != nil {
		res, err = rule(ctx, tx, req)
		if err != nil {
			return nil, false, nil, errors.Wrap(err, "signin.AccountRule()")
		}
		if res == nil || res.Outcome() != signin.ApplyStandardRule {
			return res, false, nil, nil
		}
		if res.Tenant() != "" {
			tenant = res.Tenant()
		}
	}
	if standard == "" {
		return nil, false, nil, errors.Newf("the %s sign-in method has no standard account rule: its account rule must decide the identity itself", req.Identity.Method)
	}

	return standardRule(ctx, d, tx, req, standard, tenant)
}

// standardRule applies the standard account rule to an unlinked identity, inside tx.
// Every standard rule refuses a guest of the directory, a token asserting no
// application role when the method synchronizes roles, and an identity without a
// sign-in name, before any row is written. A pre-created user under the sign-in name,
// matched without regard to case, is confirmed with its password when it has one and
// linked when it has none (applyResolution refuses the link when such a user already
// signs in through another connection). A person no user was created for is
// provisioned under the sign-in name, or refused by the invited-users-only rule unless
// the sign-in carries an invitation, which that rule takes as the account it asks for.
func standardRule[Tx any](
	ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, rule signin.StandardAccountRule, tenant string,
) (res *signin.Resolution, byInvitation bool, stop, err error) {
	switch {
	case req.Identity.Guest:
		return nil, false, Refusal("", sessioninfo.RefusedGuestAccount, signin.ErrGuestAccount, "guest accounts are not members of the directory"), nil
	case req.RoleNames != nil && len(req.RoleNames) == 0:
		return nil, false, Refusal("", sessioninfo.RefusedNoRoles, signin.ErrNoRoles, "Unauthorized: user has no roles"), nil
	case req.Identity.SignInName == "":
		return nil, false, Refusal("", sessioninfo.RefusedNoEmail, signin.ErrNoSignInName, "the identity carries no sign-in name"), nil
	}

	user, err := d.UserByUsernameIn(ctx, tx, req.Identity.SignInName)
	if err != nil {
		return nil, false, nil, errors.Wrap(err, "Driver.UserByUsernameIn()")
	}
	switch {
	case user != nil && user.HasPassword:
		return signin.Confirm(user.ID, signin.Tenant(tenant)), false, nil, nil
	case user != nil:
		return signin.Link(user.ID, false, signin.Tenant(tenant)), false, nil, nil
	}

	switch rule {
	case signin.MembersOfDirectory, signin.OpenSignUp:
		return signin.Provision(&signin.NewUser{Username: req.Identity.SignInName}, nil, signin.Tenant(tenant)), false, nil, nil
	case signin.InvitedUsersOnly:
		// The invitation the browser carries is the account the rule asks for: the
		// person was invited by address, and whoever follows the link is the invitee.
		if req.Invitation != nil {
			return signin.Provision(&signin.NewUser{Username: req.Identity.SignInName}, nil, signin.Tenant(tenant)), true, nil, nil
		}

		return nil, false, Refusal("", sessioninfo.RefusedNotInvited, signin.ErrNotInvited, "no account was created for this person"), nil
	default:
		return nil, false, nil, errors.Newf("unknown standard account rule %q", string(rule))
	}
}

// applyResolution acts on the account rules' answer for an unlinked identity. A link
// or a new user sets req.UserID (and req.Username for a new user) and reports how
// the user was found and its tenant. A pending confirmation or a refusal is returned
// as stop. invited says the sign-in carries a live invitation, whose address a new
// user takes.
func applyResolution[Tx any](
	ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, res *signin.Resolution, invited bool,
) (source sessioninfo.UserSource, tenant string, stop, err error) {
	if res == nil {
		res = signin.Reject("")
	}

	switch res.Outcome() {
	case signin.RejectIdentity:
		return "", "", Refusal(res.Refusal(), sessioninfo.RefusedIdentityRejected, signin.ErrIdentityRejected, "identity rejected"), nil
	case signin.LinkIdentity:
		// The row is held until the transaction ends, so two link decisions for one
		// user run one after the other and the second sees the first's link.
		user, err := d.LockUserIn(ctx, tx, res.UserID())
		if err != nil {
			return "", "", nil, errors.Wrap(err, "Driver.LockUserIn()")
		}
		if user.HasPassword && !res.Trusted() {
			return "", "", Refusal("", sessioninfo.RefusedIdentityRejected, signin.ErrLinkRequiresConfirmation, "identity requires confirmation"), nil
		}
		if !user.HasPassword && !res.Trusted() {
			crosses, err := linksAnotherConnection(ctx, d, tx, res.UserID(), req.Identity)
			if err != nil {
				return "", "", nil, err
			}
			if crosses {
				return "", "", Refusal("", sessioninfo.RefusedIdentityRejected, signin.ErrLinkCrossConnection, "identity from another connection needs a trusted link"), nil
			}
		}
		if err := d.LinkIdentityIn(ctx, tx, res.UserID(), req.Identity, res.Tenant()); err != nil {
			return "", "", nil, errors.Wrap(err, "Driver.LinkIdentityIn()")
		}
		req.UserID = res.UserID()

		return sessioninfo.UserNewLink, res.Tenant(), nil, nil
	case signin.ProvisionUser:
		newUser := res.NewUser()
		if newUser == nil {
			return "", "", nil, errors.New("the account rule provisioned no user: signin.Provision was given nil")
		}
		req.Username = newUser.Username
		insert := &dbtype.InsertSessionUser{Username: newUser.Username, PasswordHash: newUser.PasswordHash, Disabled: newUser.Disabled}
		if invited {
			if err := invitedAddress(ctx, d, tx, req, insert); err != nil {
				return "", "", nil, err
			}
		}
		id, err := d.InsertUserIn(ctx, tx, insert)
		if err != nil {
			return "", "", nil, errors.Wrap(err, "Driver.InsertUserIn()")
		}
		if err := d.LinkIdentityIn(ctx, tx, id, req.Identity, res.Tenant()); err != nil {
			return "", "", nil, errors.Wrap(err, "Driver.LinkIdentityIn()")
		}
		req.UserID = id
		if onProvisioned := res.OnProvisioned(); onProvisioned != nil {
			if err := onProvisioned(ctx, id); err != nil {
				return "", "", nil, errors.Wrap(err, "signin.Resolution.OnProvisioned()")
			}
		}

		return sessioninfo.UserProvisioned, res.Tenant(), nil, nil
	case signin.RequireConfirmation:
		user, err := d.UserIn(ctx, tx, res.UserID())
		if err != nil {
			return "", "", nil, errors.Wrap(err, "Driver.UserIn()")
		}

		return "", "", &signin.PendingSignInError{
			Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(res.UserID()), Username: user.Username, Tenant: res.Tenant(),
		}, nil
	case signin.ApplyStandardRule:
		return "", "", nil, errors.New("the standard account rule answered signin.Standard: a standard rule decides the identity itself")
	default:
		return "", "", nil, errors.Newf("unknown account rule outcome %d", res.Outcome())
	}
}

// invitedAddress gives a user provisioned by a sign-in that carries a live invitation
// the invitation's address, verified, when no other user holds it: the person proved
// they read it, and the row is written with it since a row buffered in this
// transaction cannot be updated in it. On a store whose usernames are the addresses
// the address is the username, verified when it is the one the invitation went to.
func invitedAddress[Tx any](ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, insert *dbtype.InsertSessionUser) error {
	inv := req.Invitation
	if d.UsernameIsEmail() {
		insert.EmailVerified = strings.EqualFold(strings.TrimSpace(insert.Username), strings.TrimSpace(inv.Email))

		return nil
	}
	holder, err := d.UserByEmailIn(ctx, tx, inv.Email)
	if err != nil {
		return errors.Wrap(err, "Driver.UserByEmailIn()")
	}
	if holder == nil {
		email := inv.Email
		insert.Email, insert.EmailVerified = &email, true
	}

	return nil
}

// decideAndInsert is the second transaction of SignIn. It reads req's user, sets
// req.User and decides the sign-in. When the sign-in goes ahead it inserts the session.
// A refusal or an MFA wait is returned after the policy's own writes commit.
func decideAndInsert[Tx any](
	ctx context.Context, d Driver[Tx], id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest,
	source sessioninfo.UserSource, tenant string, policy signin.Policy[Tx],
) error {
	base := *req
	var v verdict
	err := d.Transact(ctx, func(ctx context.Context, tx Tx) error {
		// Each run starts from the resolved request.
		*req, v = base, verdict{}

		user, err := d.UserIn(ctx, tx, req.UserID)
		if err != nil {
			return errors.Wrap(err, "Driver.UserIn()")
		}
		req.User = &sessioninfo.SignInUser{ID: req.UserID, Username: user.Username, HasPassword: user.HasPassword, Source: source, Tenant: tenant}

		var decide func(ctx context.Context) (*signin.Decision, error)
		if policy != nil {
			decide = func(ctx context.Context) (*signin.Decision, error) { return policy(ctx, tx, req) }
		}
		v, err = decideSignIn(ctx, req, user, decide)
		if err != nil {
			return err
		}
		if v.proceeds() {
			if err := d.InsertSessionIn(ctx, tx, id, insertSession, req); err != nil {
				return errors.Wrap(err, "Driver.InsertSessionIn()")
			}
		}

		// A refusal or an MFA wait commits the policy's writes without a session row.
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "Driver.Transact()")
	}

	return v.err()
}

// verdict is decideSignIn's answer. The zero verdict lets the sign-in go ahead. A
// refusal or an MFA wait travels as a value rather than an error because the
// transaction that decided it commits; the flow answers it once it has.
type verdict struct{ stop error }

// proceeds reports whether the sign-in goes ahead.
func (v verdict) proceeds() bool {
	return v.stop == nil
}

// err returns the refusal (a *sessioninfo.LoginRefusal) or the MFA wait (a
// *signin.PendingSignInError), or nil when the sign-in goes ahead.
func (v verdict) err() error {
	return v.stop
}

// decideSignIn refuses a disabled user, sets req.Username to the user's, and asks
// decide when it is non-nil and the policy applies to req.Reason. The verdict is a
// refusal, an MFA wait or the go-ahead; the transaction commits on each. err is the
// policy's error, which rolls the transaction back.
func decideSignIn(
	ctx context.Context, req *sessioninfo.NewSessionRequest, user *dbtype.User, decide func(ctx context.Context) (*signin.Decision, error),
) (verdict, error) {
	if user.Disabled {
		return verdict{stop: Refusal("", sessioninfo.RefusedUserDisabled, signin.ErrUserDisabled, "User disabled")}, nil
	}
	req.Username = user.Username

	if decide == nil || !policyApplies(req.Reason) {
		return verdict{}, nil
	}

	decision, err := decide(ctx)
	if err != nil {
		return verdict{}, errors.Wrap(err, "signin.Policy()")
	}
	if decision == nil {
		decision = signin.Deny("")
	}

	switch decision.Outcome() {
	case signin.AllowSignIn:
		return verdict{}, nil
	case signin.HoldForMFA:
		if req.Reason == sessioninfo.ReasonStepUp && completionSatisfies(decision.Factors(), req.AuthEvents) {
			return verdict{}, nil
		}
		pending := &signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(req.UserID), Username: user.Username, Factors: decision.Factors()}
		if req.User != nil {
			pending.Tenant = req.User.Tenant
		}

		return verdict{stop: pending}, nil
	default:
		return verdict{stop: Refusal(decision.Refusal(), sessioninfo.RefusedByPolicy, denialCause(decision), "sign-in denied")}, nil
	}
}

// denialCause is the cause a Deny decision's refusal carries: ErrSignInDenied, and
// with it the cause one of the library's own rules named (Decision.Cause), so
// errors.Is matches either.
func denialCause(decision *signin.Decision) error {
	if cause := decision.Cause(); cause != nil {
		return fmt.Errorf("%w: %w", signin.ErrSignInDenied, cause)
	}

	return signin.ErrSignInDenied
}

// policyApplies reports whether the sign-in policy decides a session created for
// reason. It decides ReasonLogin, ReasonIdentityLinked, ReasonExternalAuth (a session
// the application starts for a user it authenticated itself) and ReasonStepUp (an MFA
// completion, decided again with the completion's events on the request, so a tenant
// disabled or switched to require sign-on through SSO during the wait is honored).
// Every other session was decided when the session it continues was established.
func policyApplies(reason sessioninfo.NewSessionReason) bool {
	switch reason {
	case sessioninfo.ReasonLogin, sessioninfo.ReasonIdentityLinked, sessioninfo.ReasonExternalAuth, sessioninfo.ReasonStepUp:
		return true
	default:
		return false
	}
}

// completionSatisfies reports whether an MFA completion's events satisfy a RequireMFA
// answer the policy gives at the completion: any completion when the answer names no
// factor, otherwise an event by one of the factors it names. A rule that still asks
// for the factor the person just gave proceeds; one that asks for another holds the
// sign-in again.
func completionSatisfies(factors []sessioninfo.AuthMethod, events []sessioninfo.AuthEvent) bool {
	if len(factors) == 0 {
		return true
	}
	for _, e := range events {
		if slices.Contains(factors, e.Method) {
			return true
		}
	}

	return false
}

// Refusal returns a refused sign-in's error. It carries code (or fallback when code is
// empty) for the login page, cause for errors.Is, and an Unauthorized client message.
func Refusal(code, fallback sessioninfo.LoginRefusalCode, cause error, message string) error {
	if code == "" {
		code = fallback
	}

	return sessioninfo.NewLoginRefusal(code, httpio.NewUnauthorizedMessageWithError(cause, message))
}

// linksAnotherConnection reports whether identity would attach a new connection to
// userID: the user has links, and none of them is on identity's (Method, Connection).
// A user without a password cannot confirm a link, so an untrusted link of a connection
// the user does not sign in through yet is refused: the rule's evidence is the only
// check, and a custom rule must say so with trusted. A connection the user already signs in
// through, however many others they have, adds nothing and is not checked.
func linksAnotherConnection[Tx any](ctx context.Context, d Driver[Tx], tx Tx, userID ccc.UUID, identity *sessioninfo.Identity) (bool, error) {
	links, err := d.IdentitiesByUserIn(ctx, tx, userID)
	if err != nil {
		return false, errors.Wrap(err, "Driver.IdentitiesByUserIn()")
	}
	if len(links) == 0 {
		return false, nil
	}
	for _, link := range links {
		if link.Method == identity.Method && link.Connection == identity.Connection {
			return false, nil
		}
	}

	return true, nil
}
