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
// UserId, identity links (SessionIdentities) and auth events, over one database. Tx is
// the database's transaction type, pgx.Tx or *spanner.ReadWriteTransaction, which the
// sign-in hooks receive; NewPostgresAuth and NewSpannerAuth fix it.
type AuthStore[Tx any] interface {
	BaseStore
	UserStore
	// CreateSession inserts a session that has no identity to resolve and returns its
	// ID: a pending identity's row, a session the application starts for a user it
	// authenticated itself, a regeneration. A configured custom session data resolver
	// runs inside the insert transaction, except for a pending identity's row.
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
}

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
}

// NewSpannerAuth creates Spanner Auth storage over the auth schema (the base
// migrations plus schema/spanner/auth/migrations). Attach the auth events and
// impersonation tables with WithAuthEvents and WithImpersonation.
func NewSpannerAuth(client *cloudspanner.Client, opts ...SpannerOption) *Auth[*cloudspanner.ReadWriteTransaction] {
	driver := spanner.NewSessionStorageDriver(client)
	driver.EnableAuth()
	for _, opt := range opts {
		opt.applySpanner(driver)
	}

	return &Auth[*cloudspanner.ReadWriteTransaction]{userStorage: userStorage{sessionStorage: sessionStorage{db: driver}}, flow: driver}
}

// NewPostgresAuth creates PostgreSQL Auth storage over the auth schema (the base
// migrations plus schema/postgresql/auth/migrations). Attach the auth events and
// impersonation tables with WithAuthEvents and WithImpersonation.
func NewPostgresAuth(pg postgres.Queryer, opts ...PostgresOption) *Auth[pgx.Tx] {
	driver := postgres.NewSessionStorageDriver(pg)
	driver.EnableAuth()
	for _, opt := range opts {
		opt.applyPostgres(driver)
	}

	return &Auth[pgx.Tx]{userStorage: userStorage{sessionStorage: sessionStorage{db: driver}}, flow: driver}
}

// SignIn implements AuthStore.
func (a *Auth[Tx]) SignIn(ctx context.Context, req *sessioninfo.NewSessionRequest, resolve signin.UserResolver[Tx], policy signin.Policy[Tx]) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}
	now := time.Now()
	session := &dbtype.InsertSession{Username: req.Username, CreatedAt: now, UpdatedAt: now}

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
