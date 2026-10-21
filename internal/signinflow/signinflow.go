// Package signinflow establishes the session of an Auth sign-in over a storage driver:
// it resolves the identity's user, decides the sign-in and inserts the session, once
// for every driver, generic over the driver's transaction type. The drivers keep the
// SQL: each supplies the primitives, every one taking the transaction the flow opened.
package signinflow

import (
	"context"
	"fmt"
	"slices"

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
func SignIn[Tx any](
	ctx context.Context, d Driver[Tx], id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest,
	rule signin.AccountRule[Tx], standard signin.StandardAccountRule, policy signin.Policy[Tx],
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
		if rule == nil && standard == "" {
			return errors.Newf("the %s sign-in method has neither a standard account rule nor a custom one", req.Identity.Method)
		}
		var (
			stop error
			err  error
		)
		source, tenant, stop, err = resolveIdentity(ctx, d, &resolved, rule, standard)
		if err != nil {
			return err
		}
		if stop != nil {
			return stop
		}
		// The resolution has committed, so a link or a provisioned user is reported
		// even when the decision then fails.
		resolved.User = &sessioninfo.SignInUser{ID: resolved.UserID, Username: resolved.Username, Source: source, Tenant: tenant}
	case req.UserID.IsNil():
		return errors.New("a password sign-in names its user in req.UserID")
	}

	return decideAndInsert(ctx, d, id, insertSession, &resolved, source, tenant, policy)
}

// resolveIdentity is the first transaction of SignIn. It sets req.UserID (and
// req.Username for a provisioned user) and reports how the user was found and the
// link's tenant. stop is a refusal or a pending confirmation; it still commits. When two
// first sign-ins of one identity race, the loser's link fails on the identities key (a
// provisioning loser on the username first), and its resolution runs once more and
// finds the winner's link. A transaction the database ends to break a deadlock or a
// serialization failure between racing sign-ins runs once more too.
func resolveIdentity[Tx any](
	ctx context.Context, d Driver[Tx], req *sessioninfo.NewSessionRequest, rule signin.AccountRule[Tx], standard signin.StandardAccountRule,
) (source sessioninfo.UserSource, tenant string, stop, err error) {
	base := *req
	for attempt := 1; ; attempt++ {
		err = d.Transact(ctx, func(ctx context.Context, tx Tx) error {
			// Each run starts from the caller's request.
			*req = base
			var err error
			source, tenant, stop, err = resolveIn(ctx, d, tx, req, rule, standard)

			return err
		})
		if err == nil {
			return source, tenant, stop, nil
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
// their answer is applied.
func resolveIn[Tx any](
	ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, rule signin.AccountRule[Tx], standard signin.StandardAccountRule,
) (source sessioninfo.UserSource, tenant string, stop, err error) {
	link, err := d.IdentityIn(ctx, tx, req.Identity.Method, req.Identity.Connection, req.Identity.Subject)
	if err != nil {
		return "", "", nil, errors.Wrap(err, "Driver.IdentityIn()")
	}
	if link != nil {
		req.UserID = link.UserID
		if err := d.TouchIdentityIn(ctx, tx, link.ID); err != nil {
			return "", "", nil, errors.Wrap(err, "Driver.TouchIdentityIn()")
		}
		if link.Tenant != nil {
			tenant = *link.Tenant
		}

		return sessioninfo.UserExistingLink, tenant, nil, nil
	}

	res, stop, err := decideAccount(ctx, d, tx, req, rule, standard)
	if err != nil || stop != nil {
		return "", "", stop, err
	}

	return applyResolution(ctx, d, tx, req, res)
}

// decideAccount asks the account rules what to do with an unlinked identity: the
// custom rule when the registration has one, and the standard rule when it has none or
// the custom rule answers signin.Standard. A refusal the standard rule makes before any
// row is written is returned as stop. The standard rule's tenant key is the
// organization the method names, or the identity's connection when it names none,
// unless the custom rule's Standard names another.
func decideAccount[Tx any](
	ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, rule signin.AccountRule[Tx], standard signin.StandardAccountRule,
) (res *signin.Resolution, stop, err error) {
	tenant := req.Identity.Organization
	if tenant == "" {
		tenant = req.Identity.Connection
	}
	if rule != nil {
		res, err = rule(ctx, tx, req)
		if err != nil {
			return nil, nil, errors.Wrap(err, "signin.AccountRule()")
		}
		if res == nil || res.Outcome() != signin.ApplyStandardRule {
			return res, nil, nil
		}
		if res.Tenant() != "" {
			tenant = res.Tenant()
		}
	}
	if standard == "" {
		return nil, nil, errors.Newf("the %s sign-in method has no standard account rule: its account rule must decide the identity itself", req.Identity.Method)
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
// provisioned under the sign-in name, or refused by the invited-users-only rule.
func standardRule[Tx any](
	ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, rule signin.StandardAccountRule, tenant string,
) (res *signin.Resolution, stop, err error) {
	switch {
	case req.Identity.Guest:
		return nil, Refusal("", sessioninfo.RefusedGuestAccount, signin.ErrGuestAccount, "guest accounts are not members of the directory"), nil
	case req.RoleNames != nil && len(req.RoleNames) == 0:
		return nil, Refusal("", sessioninfo.RefusedNoRoles, signin.ErrNoRoles, "Unauthorized: user has no roles"), nil
	case req.Identity.SignInName == "":
		return nil, Refusal("", sessioninfo.RefusedNoEmail, signin.ErrNoSignInName, "the identity carries no sign-in name"), nil
	}

	user, err := d.UserByUsernameIn(ctx, tx, req.Identity.SignInName)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Driver.UserByUsernameIn()")
	}
	switch {
	case user != nil && user.HasPassword:
		return signin.Confirm(user.ID, signin.Tenant(tenant)), nil, nil
	case user != nil:
		return signin.Link(user.ID, false, signin.Tenant(tenant)), nil, nil
	}

	switch rule {
	case signin.MembersOfDirectory, signin.OpenSignUp:
		return signin.Provision(&signin.NewUser{Username: req.Identity.SignInName}, nil, signin.Tenant(tenant)), nil, nil
	case signin.InvitedUsersOnly:
		return nil, Refusal("", sessioninfo.RefusedNotInvited, signin.ErrNotInvited, "no account was created for this person"), nil
	default:
		return nil, nil, errors.Newf("unknown standard account rule %q", string(rule))
	}
}

// applyResolution acts on the account rules' answer for an unlinked identity. A link
// or a new user sets req.UserID (and req.Username for a new user) and reports how
// the user was found and its tenant. A pending confirmation or a refusal is returned
// as stop.
func applyResolution[Tx any](
	ctx context.Context, d Driver[Tx], tx Tx, req *sessioninfo.NewSessionRequest, res *signin.Resolution,
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
		id, err := d.InsertUserIn(ctx, tx, &dbtype.InsertSessionUser{
			Username: newUser.Username, PasswordHash: newUser.PasswordHash, Disabled: newUser.Disabled,
		})
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
