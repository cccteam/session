package sessionstorage

import (
	"context"
	"time"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// ErrIdentitiesNotConfigured is returned when an external identity needs resolution
// but the storage has no identities configuration.
var ErrIdentitiesNotConfigured = dbtype.ErrIdentitiesNotConfigured

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

// IdentityOutcome is a user resolver's decision for an external identity that is
// not yet linked to any user.
type IdentityOutcome int

const (
	// RejectIdentity refuses the sign-in with Resolution.Refusal. It is the zero value,
	// so an empty Resolution never grants access. The resolver's own writes are
	// committed.
	RejectIdentity IdentityOutcome = iota
	// LinkIdentity links the identity to Resolution.UserID and signs in. It is refused
	// for a user that has a password unless Resolution.TrustedForLinking is set.
	// Use RequireConfirmation for such a user.
	LinkIdentity
	// ProvisionUser creates the user in Resolution.NewUser (password optional),
	// links the identity to it, runs Resolution.OnProvisioned, and signs in. The
	// user and its link stay even when the sign-in policy then denies the sign-in or
	// holds it for MFA.
	ProvisionUser
	// RequireConfirmation holds the identity as pending until the user enters the
	// password of the existing user Resolution.UserID. The identity is then linked.
	RequireConfirmation
)

// Resolution is a user resolver's answer for an unlinked external identity.
type Resolution struct {
	Outcome IdentityOutcome
	// UserID is the existing user for LinkIdentity and RequireConfirmation.
	UserID ccc.UUID
	// NewUser is the user to create for ProvisionUser.
	NewUser *InsertSessionUser
	// OnProvisioned runs in the resolver's transaction after the user is created,
	// so the application can write its own rows for it. Capture the transaction in the
	// resolver's closure. The rows commit with the user, so the sign-in policy and
	// the custom session data resolver can read them.
	OnProvisioned func(ctx context.Context, userID ccc.UUID) error
	// Tenant is the application's tenant key, stored on the identity link.
	Tenant string
	// TrustedForLinking allows LinkIdentity for a user that has a password. Set it
	// only for an enterprise connection on a domain the tenant has verified.
	TrustedForLinking bool
	// Refusal is the code returned to the client for RejectIdentity.
	Refusal sessioninfo.LoginRefusalCode
}

// PolicyOutcome is a sign-in policy's decision.
type PolicyOutcome int

const (
	// DenySignIn refuses the sign-in with SignInDecision.Refusal. It is the zero value.
	// The policy's own writes are committed.
	DenySignIn PolicyOutcome = iota
	// AllowSignIn establishes the session.
	AllowSignIn
	// RequireMFA holds the sign-in as pending until the application completes its MFA
	// step and calls CompletePending.
	RequireMFA
)

// SignInDecision is a sign-in policy's answer. The policy decides every sign-in method,
// after the user is known and before a session is issued.
type SignInDecision struct {
	Outcome PolicyOutcome
	Refusal sessioninfo.LoginRefusalCode
}

// SpannerUserResolver resolves an external identity (req.Identity) that is not
// linked yet. It runs in the first of a sign-in's two transactions, which commits
// unless an error is returned; see "Storage and schema" in the README. Spanner may
// retry the transaction, so the resolver must not have side effects outside it.
type SpannerUserResolver func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*Resolution, error)

// PostgresUserResolver is the Postgres variant of SpannerUserResolver.
type PostgresUserResolver func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*Resolution, error)

// SpannerSignInPolicy decides a sign-in once its user is known, in the transaction
// that inserts the session. The user resolution has committed by then, so the policy
// can read the user and the rows the resolver wrote. req.User says how the
// user was found. The transaction commits unless an error is returned, so a
// DenySignIn or RequireMFA answer keeps the policy's own writes.
type SpannerSignInPolicy func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*SignInDecision, error)

// PostgresSignInPolicy is the Postgres variant of SpannerSignInPolicy.
type PostgresSignInPolicy func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*SignInDecision, error)

// SpannerIdentities is the validated identities configuration for Spanner storage.
type SpannerIdentities struct {
	tableName string
	resolve   SpannerUserResolver
	policy    SpannerSignInPolicy
}

// NewSpannerIdentities builds the identities configuration from the identities table
// name, the user resolver (required) and the sign-in policy (nil allows every
// sign-in).
func NewSpannerIdentities(tableName string, resolve SpannerUserResolver, policy SpannerSignInPolicy) (*SpannerIdentities, error) {
	if err := validateIdentities(tableName, resolve == nil); err != nil {
		return nil, err
	}

	return &SpannerIdentities{tableName: tableName, resolve: resolve, policy: policy}, nil
}

// PostgresIdentities is the validated identities configuration for Postgres storage.
type PostgresIdentities struct {
	tableName string
	resolve   PostgresUserResolver
	policy    PostgresSignInPolicy
}

// NewPostgresIdentities is the Postgres variant of NewSpannerIdentities.
func NewPostgresIdentities(tableName string, resolve PostgresUserResolver, policy PostgresSignInPolicy) (*PostgresIdentities, error) {
	if err := validateIdentities(tableName, resolve == nil); err != nil {
		return nil, err
	}

	return &PostgresIdentities{tableName: tableName, resolve: resolve, policy: policy}, nil
}

type spannerIdentitiesOption struct{ config *SpannerIdentities }

func (o spannerIdentitiesOption) applySpanner(driver *spanner.SessionStorageDriver) {
	if o.config == nil {
		return
	}
	driver.SetIdentities(o.config.driverConfig())
}

// WithSpannerIdentities attaches an identities configuration to Spanner Auth storage.
func WithSpannerIdentities(config *SpannerIdentities) SpannerOption {
	return spannerIdentitiesOption{config: config}
}

type postgresIdentitiesOption struct{ config *PostgresIdentities }

func (o postgresIdentitiesOption) applyPostgres(driver *postgres.SessionStorageDriver) {
	if o.config == nil {
		return
	}
	driver.SetIdentities(o.config.driverConfig())
}

// WithPostgresIdentities attaches an identities configuration to Postgres Auth storage.
func WithPostgresIdentities(config *PostgresIdentities) PostgresOption {
	return postgresIdentitiesOption{config: config}
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

// AuthStore is the storage behind an Auth session: users (SessionUsers),
// sessions with UserId, identity links, and auth events.
type AuthStore interface {
	PasswordAuthStore
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
	// IdentitiesEnabled reports whether an identities configuration is attached.
	IdentitiesEnabled() bool
}

var _ AuthStore = (*Auth)(nil)

// Auth is the storage for Auth sessions: their users, identities and auth events.
type Auth struct {
	*PasswordAuth
}

// NewSpannerAuth creates Spanner Auth storage.
func NewSpannerAuth(client *cloudspanner.Client, opts ...SpannerOption) *Auth {
	return &Auth{PasswordAuth: NewSpannerPasswordAuth(client, append([]SpannerOption{authOption{}}, opts...)...)}
}

// NewPostgresAuth creates Postgres Auth storage.
func NewPostgresAuth(pg postgres.Queryer, opts ...PostgresOption) *Auth {
	return &Auth{PasswordAuth: NewPostgresPassword(pg, append([]PostgresOption{authOption{}}, opts...)...)}
}

// Identity implements AuthStore.
func (a *Auth) Identity(ctx context.Context, method sessioninfo.AuthMethod, connection, subject string) (*SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	link, err := a.db.Identity(ctx, method, connection, subject)
	if err != nil {
		return nil, errors.Wrap(err, "db.Identity()")
	}

	return (*SessionIdentity)(link), nil
}

// IdentitiesByUser implements AuthStore.
func (a *Auth) IdentitiesByUser(ctx context.Context, userID ccc.UUID) ([]*SessionIdentity, error) {
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
func (a *Auth) LinkIdentity(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	link, err := a.db.LinkIdentity(ctx, userID, identity, tenant)
	if err != nil {
		return nil, errors.Wrap(err, "db.LinkIdentity()")
	}

	return (*SessionIdentity)(link), nil
}

// UnlinkIdentity implements AuthStore.
func (a *Auth) UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.UnlinkIdentity(ctx, identityID); err != nil {
		return errors.Wrap(err, "db.UnlinkIdentity()")
	}

	return nil
}

// DestroyUserSessions implements AuthStore.
func (a *Auth) DestroyUserSessions(ctx context.Context, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "db.DestroyUserSessions()")
	}

	return nil
}

// AppendAuthEvent implements AuthStore.
func (a *Auth) AppendAuthEvent(ctx context.Context, sessionID ccc.UUID, event *sessioninfo.AuthEvent) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.AppendAuthEvent(ctx, sessionID, event); err != nil {
		return errors.Wrap(err, "db.AppendAuthEvent()")
	}

	return nil
}

// IdentitiesEnabled implements AuthStore.
func (a *Auth) IdentitiesEnabled() bool {
	return a.db.IdentitiesEnabled()
}
