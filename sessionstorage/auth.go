package sessionstorage

import (
	"context"
	"time"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/internal/signinflow"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// ErrLastSignInMethod is returned when UnlinkIdentity would remove the last identity of
// a user that has no password. It is a Conflict client message.
var ErrLastSignInMethod = dbtype.ErrLastSignInMethod

// SessionIdentity is a stored link from an external identity to a user.
type SessionIdentity struct {
	ID          ccc.UUID               `spanner:"Id"          db:"Id"`
	UserID      ccc.UUID               `spanner:"UserId"      db:"UserId"`
	Method      sessioninfo.AuthMethod `spanner:"Method"      db:"Method"`
	Connection  string                 `spanner:"Connection"  db:"Connection"`
	Subject     string                 `spanner:"Subject"     db:"Subject"`
	Tenant      *string                `spanner:"Tenant"      db:"Tenant"`
	EmailAtLink *string                `spanner:"EmailAtLink" db:"EmailAtLink"`
	CreatedAt   time.Time              `spanner:"CreatedAt"   db:"CreatedAt"`
	LastUsedAt  time.Time              `spanner:"LastUsedAt"  db:"LastUsedAt"`
}

// AuthEventsTable names the table that records how each session was authenticated.
type AuthEventsTable struct {
	tableName string
}

// NewAuthEventsTable validates the auth events table name.
func NewAuthEventsTable(tableName string) (*AuthEventsTable, error) {
	if !validIdentifier.MatchString(tableName) {
		return nil, errors.Newf("invalid table name: %s. Table names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", tableName)
	}

	return &AuthEventsTable{tableName: tableName}, nil
}

type authEventsOption struct{ table *AuthEventsTable }

func (o authEventsOption) applySpanner(driver *spanner.SessionStorageDriver) {
	driver.SetAuthEvents(&spanner.AuthEventsConfig{TableName: o.table.tableName})
}

func (o authEventsOption) applyPostgres(driver *postgres.SessionStorageDriver) {
	driver.SetAuthEvents(&postgres.AuthEventsConfig{TableName: o.table.tableName})
}

// WithAuthEvents enables recording auth events in the given table.
func WithAuthEvents(table *AuthEventsTable) Option {
	return authEventsOption{table: table}
}

// AuthStore is the storage behind an Auth session: users (SessionUsers), sessions with
// UserId, identity links (SessionIdentities), auth events and pending sign-ins
// (SessionPendingSignIns), over one database. Tx is
// the database's transaction type, pgx.Tx or *spanner.ReadWriteTransaction, which the
// sign-in hooks receive; NewPostgresAuth and NewSpannerAuth fix it.
type AuthStore[Tx any] interface {
	BaseStore
	UserStore
	// Users lists every user, by username.
	Users(ctx context.Context) ([]*SessionUser, error)
	// SetUserPassword sets a user's password hash and whether the user must change the
	// password before anything else is served (SessionUser.PasswordChangeRequired), in
	// one write: true for a password an operator set, false for one the user chose.
	// SetUserPasswordHash leaves the mark as it is.
	SetUserPassword(ctx context.Context, id ccc.UUID, hash *securehash.Hash, changeRequired bool) error
	// CreateSession inserts a session that has no identity to resolve and returns its
	// ID: a session the application starts for a user it authenticated itself, or a
	// regeneration. A configured custom session data resolver runs inside the insert
	// transaction. A pending sign-in has no session row; see HoldSignIn.
	CreateSession(ctx context.Context, req *sessioninfo.NewSessionRequest) (ccc.UUID, error)
	// SignIn establishes the session of a sign-in that carries a verified identity
	// (req.Identity) and returns its ID. An external identity resolves to its user by its
	// link, or by the account rules when it has none: rules.Account, the registration's
	// own, when it is set, and rules.Standard, the registration's standard rule, when
	// the former is nil or answers signin.Standard, the tenants' declarations of the
	// directory deciding a stranger first when rules.Directories is set; a password
	// identity names its user in req.UserID. rules.Policy then decides, and the
	// session is inserted with its auth events and custom session data. The sign-in
	// runs in two transactions that each commit unless a hook or the storage fails: a
	// refusal (a *sessioninfo.LoginRefusal) or a wait (a *signin.PendingSignInError)
	// keeps the hooks' own writes and writes no session. See the README's "Storage and
	// schema".
	SignIn(ctx context.Context, req *sessioninfo.NewSessionRequest, rules SignInRules[Tx]) (ccc.UUID, error)
	// Identity returns the link for (method, connection, subject), or a NotFound error.
	Identity(ctx context.Context, method sessioninfo.AuthMethod, connection, subject string) (*SessionIdentity, error)
	// IdentitiesByUser lists a user's identity links.
	IdentitiesByUser(ctx context.Context, userID ccc.UUID) ([]*SessionIdentity, error)
	// LinkIdentity links an identity to a user outside the sign-in flow (for
	// example after a pending confirmation).
	LinkIdentity(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*SessionIdentity, error)
	// UnlinkIdentity removes a link. It refuses to remove the last means of sign-in of
	// a user that has no password.
	UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error
	// SetTokensTableName sets the name of the tokens table (SessionTokens).
	SetTokensTableName(name string) error
	// SetDeviceCodesTableName sets the name of the device codes table
	// (SessionDeviceCodes).
	SetDeviceCodesTableName(name string) error
	// InsertToken inserts a token: created at the database's time, unused and not
	// revoked, whatever t carries.
	InsertToken(ctx context.Context, t *Token) error
	// Token returns the token holding tokenHash that is live now: not revoked and not
	// expired. Any other is NotFound.
	Token(ctx context.Context, tokenHash []byte) (*Token, error)
	// Tokens lists the live tokens of a user, newest first.
	Tokens(ctx context.Context, userID ccc.UUID) ([]*Token, error)
	// TouchToken moves a live token's LastUsedAt to the database's time; a token that
	// is not live is left as it is.
	TouchToken(ctx context.Context, id ccc.UUID) error
	// RevokeUserToken revokes the live token id of userID with reason: the token
	// alone, or its whole family when it has one. A token that is not live, or not the
	// user's, is NotFound.
	RevokeUserToken(ctx context.Context, userID, id ccc.UUID, reason TokenRevocation) error
	// RevokeUserTokens revokes every live token of a user with reason.
	RevokeUserTokens(ctx context.Context, userID ccc.UUID, reason TokenRevocation) error
	// ExchangeRefreshToken rotates the live refresh token holding tokenHash, in one
	// transaction: it is revoked as rotated and access and refresh are inserted in its
	// family, as its user, for its outlet and client, which the store fills in on the
	// two. A token that is not a live refresh token is NotFound; one already rotated is
	// a reuse, its whole family is revoked, and the error is ErrTokenReuse.
	ExchangeRefreshToken(ctx context.Context, tokenHash []byte, access, refresh *Token) error
	// InsertDeviceCode inserts a device authorization: created at the database's time
	// and pending, whatever d carries.
	InsertDeviceCode(ctx context.Context, d *DeviceCode) error
	// DeviceCode returns the device authorization userCode names that is pending now:
	// not decided, not consumed, not expired. Any other is NotFound.
	DeviceCode(ctx context.Context, userCode string) (*DeviceCode, error)
	// ApproveDeviceCode records that userID approved the pending device code id. A
	// code that is not pending is NotFound, so one decision stands.
	ApproveDeviceCode(ctx context.Context, id, userID ccc.UUID) error
	// DenyDeviceCode records that the person denied the pending device code id. A code
	// that is not pending is NotFound.
	DenyDeviceCode(ctx context.Context, id ccc.UUID) error
	// RedeemDeviceCode is the client's poll of the device code holding deviceCodeHash,
	// in one transaction: an approved code is consumed, once, and access and refresh
	// are inserted as the approving user's for the code's outlet and client, which the
	// store fills in on the two; a pending code polled before interval passed since the
	// last poll is slow_down and nothing is written; otherwise the status says what
	// the client learned. A code that is not there or was consumed is NotFound.
	RedeemDeviceCode(ctx context.Context, deviceCodeHash []byte, interval time.Duration, access, refresh *Token) (*DeviceCode, DeviceCodeStatus, error)
	// DestroyUserSessions expires every session of a user, by UserId.
	DestroyUserSessions(ctx context.Context, userID ccc.UUID) error
	// TouchUserSignIn moves a user's LastSignInAt to the database's time. The Auth calls
	// it once a sign-in has established its session, as a write of its own: inside the
	// sign-in's transaction the update would upgrade the share lock the flow holds on
	// the user row and deadlock two sign-ins of one user.
	TouchUserSignIn(ctx context.Context, userID ccc.UUID) error
	// AppendAuthEvent records a step-up or confirmation on an existing session.
	AppendAuthEvent(ctx context.Context, sessionID ccc.UUID, event *sessioninfo.AuthEvent) error
	// DestroySessionsByProviderSessionID expires every live session whose sign-in
	// carried the provider's session id under issuer, as a provider-initiated logout
	// asks; an impersonated session's record ends Logout. Both columns match: a session
	// recorded without an issuer never does.
	DestroySessionsByProviderSessionID(ctx context.Context, issuer, providerSessionID string) error
	// SetIdentitiesTableName sets the name of the identities table. (default: SessionIdentities)
	SetIdentitiesTableName(name string) error
	// SetPendingSignInsTableName sets the name of the pending sign-ins table. (default: SessionPendingSignIns)
	SetPendingSignInsTableName(name string) error
	// HoldSignIn stores a sign-in that waits for a confirmation or the application's MFA
	// step and returns its row's ID. p.TokenHash is the hash of the opaque token the
	// browser's pending cookie carries.
	HoldSignIn(ctx context.Context, p *PendingSignIn) (ccc.UUID, error)
	// PendingSignIn returns the live pending sign-in holding tokenHash: not consumed and
	// not expired. Any other is NotFound.
	PendingSignIn(ctx context.Context, tokenHash []byte) (*PendingSignIn, error)
	// ConsumePendingSignIn consumes the live pending sign-in holding tokenHash by a
	// conditional update, so it is consumed once; a pending sign-in that is not live
	// (consumed, expired or unknown) is NotFound.
	ConsumePendingSignIn(ctx context.Context, tokenHash []byte) error
	// SetSignInAttemptsTableName sets the name of the sign-in attempts table. (default: SessionSignInAttempts)
	SetSignInAttemptsTableName(name string) error
	// SignInAttempts returns the sign-in attempts record of name, the submitted name as
	// the Auth normalized it: its failed password attempts in the window and its lock.
	// A name with no record is NotFound.
	SignInAttempts(ctx context.Context, name string) (*SignInAttempts, error)
	// RecordSignInFailure records a failed password attempt on name, at the time of
	// the call, under limit, and returns the record as written: the failure counts in
	// the name's window, or opens one, and the failure that reaches limit.Failures
	// locks the name for limit.Lock; a name that is locked is left as it is. The read
	// and the write are one transaction, so concurrent failures each count.
	RecordSignInFailure(ctx context.Context, name string, limit SignInAttemptLimit) (*SignInAttempts, error)
	// ClearSignInAttempts deletes the sign-in attempts record of name: a successful
	// password check, an MFA completion and a password change reset the count.
	ClearSignInAttempts(ctx context.Context, name string) error
	// SetMailLinksTableName sets the name of the mail links table. (default: SessionMailLinks)
	SetMailLinksTableName(name string) error
	// SetUsernameIsEmail declares the users table in the shape where the address is
	// the username, generated by the database: the store never writes Email, refuses
	// a rename, and writes a verified address as the username (see the README's
	// "Users and their email address"). The password method's UsernameIsEmail option
	// sets it.
	SetUsernameIsEmail(same bool)
	// UsernameIsEmail reports whether the address is the username.
	UsernameIsEmail() bool
	// UserByEmail returns the user holding the address, verified or not, matched
	// without regard to case, or a NotFound error.
	UserByEmail(ctx context.Context, email string) (*SessionUser, error)
	// SetUserEmail puts an address on a user by hand, unverified, or takes it off
	// (nil): an administrator's entry, which reserves the address. An address another
	// user holds is a Conflict; on a store whose usernames are the addresses the
	// entry is refused.
	SetUserEmail(ctx context.Context, id ccc.UUID, email *string) error
	// VerifyUserEmail writes the address the person has just proven they read,
	// verified at the database's time, replacing whatever the user held; on a store
	// whose usernames are the addresses it is written as the username, renaming the
	// user and its live sessions. An address another user holds is a Conflict.
	VerifyUserEmail(ctx context.Context, id ccc.UUID, email string) error
	// ClaimVerifiedEmail writes email on the user as verified when the user holds no
	// verified address yet and no other user holds it, and reports whether it wrote:
	// a Google sign-in's verified address. On a store whose usernames are the
	// addresses only the verified time is written, and only when the address is the
	// username.
	ClaimVerifiedEmail(ctx context.Context, id ccc.UUID, email string) (bool, error)
	// InsertMailLink stores a mailed link's row: l.TokenHash is the hash of the opaque
	// token the mail carries. The row's ID is set on l.
	InsertMailLink(ctx context.Context, l *MailLink) error
	// MailLink returns the live mail link holding tokenHash: not consumed and not
	// expired. Any other is NotFound.
	MailLink(ctx context.Context, tokenHash []byte) (*MailLink, error)
	// LiveMailLinks lists the live links of kind, oldest first: the invitations that
	// still stand.
	LiveMailLinks(ctx context.Context, kind MailLinkKind) ([]*MailLink, error)
	// ConsumeMailLink consumes the live mail link holding tokenHash by a conditional
	// update, so it is consumed once; a link that is not live is NotFound.
	ConsumeMailLink(ctx context.Context, tokenHash []byte) error
	// RevokeMailLink consumes the live mail link id: an invitation withdrawn by hand.
	// A link that is not live is NotFound.
	RevokeMailLink(ctx context.Context, id ccc.UUID) error
	// AcceptInvitation accepts inv for user userID in one transaction: the
	// invitation is consumed and the user's address is set from it when the user
	// holds no verified address, in one transaction; once it has committed, accept,
	// the application's hook, grants what the invitation names, outside any
	// transaction; nil for none. An invitation that is no longer live is NotFound,
	// and nothing is written.
	AcceptInvitation(ctx context.Context, userID ccc.UUID, username string, inv *sessioninfo.Invitation, accept signinflow.InvitationAcceptor) error
}

// MailLink is a row of the mail links table: one single-use link the library mailed.
type MailLink = dbtype.MailLink

// MailLinkKind is what a mailed link does when it is followed.
type MailLinkKind = dbtype.MailLinkKind

// The mail link kinds.
const (
	MailLinkInvitation   = dbtype.MailLinkInvitation
	MailLinkVerification = dbtype.MailLinkVerification
	MailLinkSignUp       = dbtype.MailLinkSignUp
)

// SignInAttempts is the sign-in attempts record of a name: the failed password
// attempts in its window and the lock they earned.
type SignInAttempts = dbtype.SignInAttempts

// SignInAttemptLimit is the rule a failure is recorded under: Failures within Window
// lock the name for Lock.
type SignInAttemptLimit = dbtype.SignInAttemptLimit

// PendingSignIn is a sign-in held in the pending sign-ins table until its confirmation
// or MFA step.
type PendingSignIn = dbtype.PendingSignIn

// Token is a row of the tokens table: one bearer credential of a machine outlet. See
// dbtype.Token.
type Token = dbtype.Token

// TokenKind is what a token is: an application token a person issued, or the access
// or refresh token of a device grant.
type TokenKind = dbtype.TokenKind

// The token kinds.
const (
	TokenApplication = dbtype.TokenApplication
	TokenAccess      = dbtype.TokenAccess
	TokenRefresh     = dbtype.TokenRefresh
)

// TokenRevocation says why a token was revoked.
type TokenRevocation = dbtype.TokenRevocation

// The token revocations.
const (
	TokenRevokedByHand   = dbtype.TokenRevokedByHand
	TokenRevokedRotated  = dbtype.TokenRevokedRotated
	TokenRevokedReuse    = dbtype.TokenRevokedReuse
	TokenRevokedWithUser = dbtype.TokenRevokedWithUser
)

// ErrTokenReuse is the error of a refresh exchange given a token already rotated: the
// family is revoked.
var ErrTokenReuse = dbtype.ErrTokenReuse

// DeviceCode is a row of the device codes table: one device authorization a
// command-line client started. See dbtype.DeviceCode.
type DeviceCode = dbtype.DeviceCode

// DeviceCodeStatus is what a client's poll of its device code learned.
type DeviceCodeStatus = dbtype.DeviceCodeStatus

// The device code statuses.
const (
	DevicePending  = dbtype.DevicePending
	DeviceSlowDown = dbtype.DeviceSlowDown
	DeviceApproved = dbtype.DeviceApproved
	DeviceDenied   = dbtype.DeviceDenied
	DeviceExpired  = dbtype.DeviceExpired
)

var (
	_ AuthStore[pgx.Tx]                             = (*Auth[pgx.Tx])(nil)
	_ AuthStore[*cloudspanner.ReadWriteTransaction] = (*Auth[*cloudspanner.ReadWriteTransaction])(nil)
)

// Auth is the storage for Auth sessions: their users, identities and auth events. Tx is
// the database's transaction type.
type Auth[Tx any] struct {
	userStorage
	// flow is the driver as the sign-in flow drives it, typed by its transaction.
	flow signinflow.Driver[Tx]
	// custom attaches the custom data configurations to the driver.
	custom customDataAttacher[Tx]
}

// NewSpannerAuth creates Spanner Auth storage over the auth schema (the base
// migrations plus schema/spanner/auth/migrations). Attach the auth events and
// impersonation tables with WithAuthEvents and WithImpersonation, and custom session
// and user data with the store's WithCustomSessionData and WithCustomUserData.
func NewSpannerAuth(client *cloudspanner.Client, opts ...SpannerOption) *Auth[*cloudspanner.ReadWriteTransaction] {
	driver := spanner.NewSessionStorageDriver(client)
	driver.EnableAuth()
	for _, opt := range opts {
		opt.applySpanner(driver)
	}

	return &Auth[*cloudspanner.ReadWriteTransaction]{userStorage: userStorage{sessionStorage: sessionStorage{db: driver}}, flow: driver, custom: spannerCustomData{driver}}
}

// NewPostgresAuth creates PostgreSQL Auth storage over the auth schema (the base
// migrations plus schema/postgresql/auth/migrations). Attach the auth events and
// impersonation tables with WithAuthEvents and WithImpersonation, and custom session
// and user data with the store's WithCustomSessionData and WithCustomUserData.
func NewPostgresAuth(pg postgres.Queryer, opts ...PostgresOption) *Auth[pgx.Tx] {
	driver := postgres.NewSessionStorageDriver(pg)
	driver.EnableAuth()
	for _, opt := range opts {
		opt.applyPostgres(driver)
	}

	return &Auth[pgx.Tx]{userStorage: userStorage{sessionStorage: sessionStorage{db: driver}}, flow: driver, custom: postgresCustomData{driver}}
}

// SignInRules are the application's rules a sign-in runs under, handed to
// AuthStore.SignIn: the registration's own account rule (nil for none) and its standard
// rule ("" for none), the sign-in policy (nil for none), the invitation acceptor (nil
// for none), and a tenanted application's reader of the tenants' directory
// declarations with the hook that seats a stranger they admit (both nil for none).
type SignInRules[Tx any] struct {
	Account     signin.AccountRule[Tx]
	Standard    signin.StandardAccountRule
	Policy      signin.Policy[Tx]
	Accept      signinflow.InvitationAcceptor
	Directories signin.DirectoryReader[Tx]
	Roles       signin.UserRoleManager
	Seat        signinflow.DirectorySeater
}

// SignIn implements AuthStore.
func (a *Auth[Tx]) SignIn(ctx context.Context, req *sessioninfo.NewSessionRequest, rules SignInRules[Tx]) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}
	session := &dbtype.InsertSession{Username: req.Username}

	flowRules := signinflow.Rules[Tx]{
		Account: rules.Account, Standard: rules.Standard, Policy: rules.Policy, Accept: rules.Accept,
		Directories: rules.Directories, Roles: rules.Roles, Seat: rules.Seat,
	}
	if err := signinflow.SignIn(ctx, a.flow, id, session, req, flowRules); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "signinflow.SignIn()")
	}

	return id, nil
}

// AcceptInvitation implements AuthStore.
func (a *Auth[Tx]) AcceptInvitation(ctx context.Context, userID ccc.UUID, username string, inv *sessioninfo.Invitation, accept signinflow.InvitationAcceptor) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := signinflow.AcceptInvitation(ctx, a.flow, userID, username, inv, accept); err != nil {
		return errors.Wrap(err, "signinflow.AcceptInvitation()")
	}

	return nil
}

// SetMailLinksTableName implements AuthStore.
func (a *Auth[Tx]) SetMailLinksTableName(name string) error {
	if err := a.db.SetMailLinksTableName(name); err != nil {
		return errors.Wrap(err, "db.SetMailLinksTableName()")
	}

	return nil
}

// SetUsernameIsEmail implements AuthStore.
func (a *Auth[Tx]) SetUsernameIsEmail(same bool) {
	a.db.SetUsernameIsEmail(same)
}

// UsernameIsEmail implements AuthStore.
func (a *Auth[Tx]) UsernameIsEmail() bool {
	return a.db.UsernameIsEmail()
}

// UserByEmail implements AuthStore.
func (a *Auth[Tx]) UserByEmail(ctx context.Context, email string) (*SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	user, err := a.db.UserByEmail(ctx, email)
	if err != nil {
		return nil, errors.Wrap(err, "db.UserByEmail()")
	}

	return user, nil
}

// SetUserEmail implements AuthStore.
func (a *Auth[Tx]) SetUserEmail(ctx context.Context, id ccc.UUID, email *string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.SetUserEmail(ctx, id, email); err != nil {
		return errors.Wrap(err, "db.SetUserEmail()")
	}

	return nil
}

// VerifyUserEmail implements AuthStore.
func (a *Auth[Tx]) VerifyUserEmail(ctx context.Context, id ccc.UUID, email string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.VerifyUserEmail(ctx, id, email); err != nil {
		return errors.Wrap(err, "db.VerifyUserEmail()")
	}

	return nil
}

// ClaimVerifiedEmail implements AuthStore.
func (a *Auth[Tx]) ClaimVerifiedEmail(ctx context.Context, id ccc.UUID, email string) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	claimed, err := a.db.ClaimVerifiedEmail(ctx, id, email)
	if err != nil {
		return false, errors.Wrap(err, "db.ClaimVerifiedEmail()")
	}

	return claimed, nil
}

// InsertMailLink implements AuthStore.
func (a *Auth[Tx]) InsertMailLink(ctx context.Context, l *MailLink) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return errors.Wrap(err, "ccc.NewUUID()")
	}
	l.ID = id
	if err := a.db.InsertMailLink(ctx, l); err != nil {
		return errors.Wrap(err, "db.InsertMailLink()")
	}

	return nil
}

// MailLink implements AuthStore.
func (a *Auth[Tx]) MailLink(ctx context.Context, tokenHash []byte) (*MailLink, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	l, err := a.db.MailLinkByToken(ctx, tokenHash, time.Now())
	if err != nil {
		return nil, errors.Wrap(err, "db.MailLinkByToken()")
	}

	return l, nil
}

// LiveMailLinks implements AuthStore.
func (a *Auth[Tx]) LiveMailLinks(ctx context.Context, kind MailLinkKind) ([]*MailLink, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	links, err := a.db.LiveMailLinks(ctx, kind, time.Now())
	if err != nil {
		return nil, errors.Wrap(err, "db.LiveMailLinks()")
	}

	return links, nil
}

// ConsumeMailLink implements AuthStore.
func (a *Auth[Tx]) ConsumeMailLink(ctx context.Context, tokenHash []byte) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.ConsumeMailLink(ctx, tokenHash, time.Now()); err != nil {
		return errors.Wrap(err, "db.ConsumeMailLink()")
	}

	return nil
}

// RevokeMailLink implements AuthStore.
func (a *Auth[Tx]) RevokeMailLink(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.RevokeMailLink(ctx, id, time.Now()); err != nil {
		return errors.Wrap(err, "db.RevokeMailLink()")
	}

	return nil
}

// Users implements AuthStore.
func (a *Auth[Tx]) Users(ctx context.Context) ([]*SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	users, err := a.db.Users(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "db.Users()")
	}

	return users, nil
}

// SetUserPassword implements AuthStore.
func (a *Auth[Tx]) SetUserPassword(ctx context.Context, id ccc.UUID, hash *securehash.Hash, changeRequired bool) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.SetUserPassword(ctx, id, hash, changeRequired); err != nil {
		return errors.Wrap(err, "db.SetUserPassword()")
	}

	return nil
}

// Identity implements AuthStore.
func (a *Auth[Tx]) Identity(ctx context.Context, method sessioninfo.AuthMethod, connection, subject string) (*SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	link, err := a.db.Identity(ctx, method, connection, subject)
	if err != nil {
		return nil, errors.Wrap(err, "db.Identity()")
	}

	return (*SessionIdentity)(link), nil
}

// IdentitiesByUser implements AuthStore.
func (a *Auth[Tx]) IdentitiesByUser(ctx context.Context, userID ccc.UUID) ([]*SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	links, err := a.db.IdentitiesByUser(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "db.IdentitiesByUser()")
	}

	identities := make([]*SessionIdentity, len(links))
	for i, link := range links {
		identities[i] = (*SessionIdentity)(link)
	}

	return identities, nil
}

// LinkIdentity implements AuthStore.
func (a *Auth[Tx]) LinkIdentity(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	link, err := a.db.LinkIdentity(ctx, userID, identity, tenant)
	if err != nil {
		return nil, errors.Wrap(err, "db.LinkIdentity()")
	}

	return (*SessionIdentity)(link), nil
}

// UnlinkIdentity implements AuthStore.
func (a *Auth[Tx]) UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.UnlinkIdentity(ctx, identityID); err != nil {
		return errors.Wrap(err, "db.UnlinkIdentity()")
	}

	return nil
}

// DestroyUserSessions implements AuthStore.
func (a *Auth[Tx]) DestroyUserSessions(ctx context.Context, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "db.DestroyUserSessions()")
	}

	return nil
}

// TouchUserSignIn implements AuthStore.
func (a *Auth[Tx]) TouchUserSignIn(ctx context.Context, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.TouchUserSignIn(ctx, userID); err != nil {
		return errors.Wrap(err, "db.TouchUserSignIn()")
	}

	return nil
}

// AppendAuthEvent implements AuthStore.
func (a *Auth[Tx]) AppendAuthEvent(ctx context.Context, sessionID ccc.UUID, event *sessioninfo.AuthEvent) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.AppendAuthEvent(ctx, sessionID, event); err != nil {
		return errors.Wrap(err, "db.AppendAuthEvent()")
	}

	return nil
}

// HoldSignIn implements AuthStore.
func (a *Auth[Tx]) HoldSignIn(ctx context.Context, p *PendingSignIn) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}
	p.ID = id
	if err := a.db.InsertPendingSignIn(ctx, p); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "db.InsertPendingSignIn()")
	}

	return id, nil
}

// PendingSignIn implements AuthStore.
func (a *Auth[Tx]) PendingSignIn(ctx context.Context, tokenHash []byte) (*PendingSignIn, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	p, err := a.db.PendingSignInByToken(ctx, tokenHash, time.Now())
	if err != nil {
		return nil, errors.Wrap(err, "db.PendingSignInByToken()")
	}

	return p, nil
}

// ConsumePendingSignIn implements AuthStore.
func (a *Auth[Tx]) ConsumePendingSignIn(ctx context.Context, tokenHash []byte) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.ConsumePendingSignIn(ctx, tokenHash, time.Now()); err != nil {
		return errors.Wrap(err, "db.ConsumePendingSignIn()")
	}

	return nil
}

// SetIdentitiesTableName implements AuthStore.
func (a *Auth[Tx]) SetIdentitiesTableName(name string) error {
	if err := a.db.SetIdentitiesTableName(name); err != nil {
		return errors.Wrap(err, "db.SetIdentitiesTableName()")
	}

	return nil
}

// SetPendingSignInsTableName implements AuthStore.
func (a *Auth[Tx]) SetPendingSignInsTableName(name string) error {
	if err := a.db.SetPendingSignInsTableName(name); err != nil {
		return errors.Wrap(err, "db.SetPendingSignInsTableName()")
	}

	return nil
}

// DestroySessionsByProviderSessionID implements AuthStore.
func (a *Auth[Tx]) DestroySessionsByProviderSessionID(ctx context.Context, issuer, providerSessionID string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.DestroySessionsByProviderSessionID(ctx, issuer, providerSessionID); err != nil {
		return errors.Wrap(err, "db.DestroySessionsByProviderSessionID()")
	}

	return nil
}

// SetSignInAttemptsTableName implements AuthStore.
func (a *Auth[Tx]) SetSignInAttemptsTableName(name string) error {
	if err := a.db.SetSignInAttemptsTableName(name); err != nil {
		return errors.Wrap(err, "db.SetSignInAttemptsTableName()")
	}

	return nil
}

// SignInAttempts implements AuthStore.
func (a *Auth[Tx]) SignInAttempts(ctx context.Context, name string) (*SignInAttempts, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	record, err := a.db.SignInAttempts(ctx, name)
	if err != nil {
		return nil, errors.Wrap(err, "db.SignInAttempts()")
	}

	return record, nil
}

// RecordSignInFailure implements AuthStore.
func (a *Auth[Tx]) RecordSignInFailure(ctx context.Context, name string, limit SignInAttemptLimit) (*SignInAttempts, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	record, err := a.db.RecordSignInFailure(ctx, name, time.Now(), limit)
	if err != nil {
		return nil, errors.Wrap(err, "db.RecordSignInFailure()")
	}

	return record, nil
}

// ClearSignInAttempts implements AuthStore.
func (a *Auth[Tx]) ClearSignInAttempts(ctx context.Context, name string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.ClearSignInAttempts(ctx, name); err != nil {
		return errors.Wrap(err, "db.ClearSignInAttempts()")
	}

	return nil
}

// SetTokensTableName implements AuthStore.
func (a *Auth[Tx]) SetTokensTableName(name string) error {
	if err := a.db.SetTokensTableName(name); err != nil {
		return errors.Wrap(err, "db.SetTokensTableName()")
	}

	return nil
}

// SetDeviceCodesTableName implements AuthStore.
func (a *Auth[Tx]) SetDeviceCodesTableName(name string) error {
	if err := a.db.SetDeviceCodesTableName(name); err != nil {
		return errors.Wrap(err, "db.SetDeviceCodesTableName()")
	}

	return nil
}

// InsertToken implements AuthStore.
func (a *Auth[Tx]) InsertToken(ctx context.Context, t *Token) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.InsertToken(ctx, t); err != nil {
		return errors.Wrap(err, "db.InsertToken()")
	}

	return nil
}

// Token implements AuthStore.
func (a *Auth[Tx]) Token(ctx context.Context, tokenHash []byte) (*Token, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	t, err := a.db.TokenByHash(ctx, tokenHash, time.Now())
	if err != nil {
		return nil, errors.Wrap(err, "db.TokenByHash()")
	}

	return t, nil
}

// Tokens implements AuthStore.
func (a *Auth[Tx]) Tokens(ctx context.Context, userID ccc.UUID) ([]*Token, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	tokens, err := a.db.TokensByUser(ctx, userID, time.Now())
	if err != nil {
		return nil, errors.Wrap(err, "db.TokensByUser()")
	}

	return tokens, nil
}

// TouchToken implements AuthStore.
func (a *Auth[Tx]) TouchToken(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.TouchToken(ctx, id, time.Now()); err != nil {
		return errors.Wrap(err, "db.TouchToken()")
	}

	return nil
}

// RevokeUserToken implements AuthStore.
func (a *Auth[Tx]) RevokeUserToken(ctx context.Context, userID, id ccc.UUID, reason TokenRevocation) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.RevokeUserToken(ctx, userID, id, time.Now(), reason); err != nil {
		return errors.Wrap(err, "db.RevokeUserToken()")
	}

	return nil
}

// RevokeUserTokens implements AuthStore.
func (a *Auth[Tx]) RevokeUserTokens(ctx context.Context, userID ccc.UUID, reason TokenRevocation) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.RevokeUserTokens(ctx, userID, reason); err != nil {
		return errors.Wrap(err, "db.RevokeUserTokens()")
	}

	return nil
}

// ExchangeRefreshToken implements AuthStore.
func (a *Auth[Tx]) ExchangeRefreshToken(ctx context.Context, tokenHash []byte, access, refresh *Token) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.ExchangeRefreshToken(ctx, tokenHash, time.Now(), access, refresh); err != nil {
		return errors.Wrap(err, "db.ExchangeRefreshToken()")
	}

	return nil
}

// InsertDeviceCode implements AuthStore.
func (a *Auth[Tx]) InsertDeviceCode(ctx context.Context, d *DeviceCode) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.InsertDeviceCode(ctx, d); err != nil {
		return errors.Wrap(err, "db.InsertDeviceCode()")
	}

	return nil
}

// DeviceCode implements AuthStore.
func (a *Auth[Tx]) DeviceCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	d, err := a.db.DeviceCodeByUserCode(ctx, userCode, time.Now())
	if err != nil {
		return nil, errors.Wrap(err, "db.DeviceCodeByUserCode()")
	}

	return d, nil
}

// ApproveDeviceCode implements AuthStore.
func (a *Auth[Tx]) ApproveDeviceCode(ctx context.Context, id, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.ApproveDeviceCode(ctx, id, userID, time.Now()); err != nil {
		return errors.Wrap(err, "db.ApproveDeviceCode()")
	}

	return nil
}

// DenyDeviceCode implements AuthStore.
func (a *Auth[Tx]) DenyDeviceCode(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.DenyDeviceCode(ctx, id, time.Now()); err != nil {
		return errors.Wrap(err, "db.DenyDeviceCode()")
	}

	return nil
}

// RedeemDeviceCode implements AuthStore.
func (a *Auth[Tx]) RedeemDeviceCode(ctx context.Context, deviceCodeHash []byte, interval time.Duration, access, refresh *Token) (code *DeviceCode, status DeviceCodeStatus, err error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	d, status, err := a.db.RedeemDeviceCode(ctx, deviceCodeHash, time.Now(), interval, access, refresh)
	if err != nil {
		return nil, "", errors.Wrap(err, "db.RedeemDeviceCode()")
	}

	return d, status, nil
}
