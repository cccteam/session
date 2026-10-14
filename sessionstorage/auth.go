package sessionstorage

import (
	"context"
	"time"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
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
	// CreateSession inserts a session that has no identity to resolve and returns its
	// ID: a session the application starts for a user it authenticated itself, or a
	// regeneration. A configured custom session data resolver runs inside the insert
	// transaction. A pending sign-in has no session row; see HoldSignIn.
	CreateSession(ctx context.Context, req *sessioninfo.NewSessionRequest) (ccc.UUID, error)
	// SignIn establishes the session of a sign-in that carries a verified identity
	// (req.Identity) and returns its ID. An external identity resolves to its user by its
	// link, or by resolve when it has none; a password identity names its user in
	// req.UserID. policy then decides, and the session is inserted with its auth events
	// and custom session data. The sign-in runs in two transactions that each commit
	// unless a hook or the storage fails: a refusal (a *sessioninfo.LoginRefusal) or a
	// wait (a *signin.PendingSignInError) keeps the hooks' own writes and writes no
	// session. See the README's "Storage and schema".
	SignIn(ctx context.Context, req *sessioninfo.NewSessionRequest, resolve signin.UserResolver[Tx], policy signin.Policy[Tx]) (ccc.UUID, error)
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
}

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
func (a *Auth[Tx]) SignIn(ctx context.Context, req *sessioninfo.NewSessionRequest, resolve signin.UserResolver[Tx], policy signin.Policy[Tx]) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}
	session := &dbtype.InsertSession{Username: req.Username}

	if err := signinflow.SignIn(ctx, a.flow, id, session, req, resolve, policy); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "signinflow.SignIn()")
	}

	return id, nil
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
