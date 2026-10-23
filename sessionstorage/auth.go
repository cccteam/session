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
	// link, or by the account rules when it has none: rule, the registration's own,
	// when it is set, and standard, the registration's standard rule, when rule is nil
	// or answers signin.Standard; a password identity names its user in req.UserID.
	// policy then decides, and the session is inserted with its auth events and custom
	// session data. The sign-in runs in two transactions that each commit unless a hook
	// or the storage fails: a refusal (a *sessioninfo.LoginRefusal) or a wait (a
	// *signin.PendingSignInError) keeps the hooks' own writes and writes no session. See
	// the README's "Storage and schema".
	SignIn(
		ctx context.Context, req *sessioninfo.NewSessionRequest, rule signin.AccountRule[Tx], standard signin.StandardAccountRule, policy signin.Policy[Tx],
		accept signinflow.InvitationAcceptor,
	) (ccc.UUID, error)
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

// SignIn implements AuthStore.
func (a *Auth[Tx]) SignIn(
	ctx context.Context, req *sessioninfo.NewSessionRequest, rule signin.AccountRule[Tx], standard signin.StandardAccountRule, policy signin.Policy[Tx],
	accept signinflow.InvitationAcceptor,
) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}
	session := &dbtype.InsertSession{Username: req.Username}

	if err := signinflow.SignIn(ctx, a.flow, id, session, req, signinflow.Rules[Tx]{Account: rule, Standard: standard, Policy: policy, Accept: accept}); err != nil {
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
