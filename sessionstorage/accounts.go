package sessionstorage

// CONTRACT (multi-method sessions, v0.13.0): the exported types, constructors and
// signatures in this file are the agreed contract. Bodies are stubs until the
// implementation lands; see docs/multi-method-auth.md.

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

// ErrIdentitiesNotConfigured is returned when an Auth session needs identity
// resolution but the storage has no identities configuration attached.
var ErrIdentitiesNotConfigured = dbtype.ErrIdentitiesNotConfigured

// SessionIdentity is a stored link from an external identity to an account.
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

// IdentityOutcome is an account resolver's decision for an external identity that is
// not yet linked to any account.
type IdentityOutcome int

const (
	// RejectIdentity refuses the sign-in; Resolution.Refusal says why. It is the zero
	// value, so an empty Resolution never grants access. The resolver's own writes in
	// its transaction are committed (for example a record of the refused attempt).
	RejectIdentity IdentityOutcome = iota
	// LinkIdentity links the identity to Resolution.UserID and signs in. The library
	// refuses this outcome for an account that has a password unless the connection
	// opted in with Resolution.TrustedForLinking; use RequireConfirmation instead.
	LinkIdentity
	// ProvisionAccount creates the account in Resolution.NewUser (password optional),
	// links the identity to it, runs Resolution.OnProvisioned, and signs in. The
	// account and its link are committed before the sign-in policy decides, so they
	// stay when the policy denies the sign-in or holds it for MFA.
	ProvisionAccount
	// RequireConfirmation holds the identity as pending until the user confirms the
	// password of the existing account Resolution.UserID; then it is linked.
	RequireConfirmation
)

// Resolution is an account resolver's answer for an unlinked external identity.
type Resolution struct {
	Outcome IdentityOutcome
	// UserID is the existing account for LinkIdentity and RequireConfirmation.
	UserID ccc.UUID
	// NewUser is the account to create for ProvisionAccount.
	NewUser *InsertSessionUser
	// OnProvisioned runs inside the resolver's transaction after the account is
	// created, so the application can create its own rows for the new account; they
	// commit with the account, before the sign-in policy and the custom session data
	// resolver run, which read them. The resolver closure captures its transaction.
	OnProvisioned func(ctx context.Context, userID ccc.UUID) error
	// Tenant is the application's tenant key, stored on the identity link.
	Tenant string
	// TrustedForLinking allows LinkIdentity for an account that has a password. Only
	// set it for an enterprise connection on a domain the tenant has verified.
	TrustedForLinking bool
	// Refusal is the code returned to the client for RejectIdentity.
	Refusal sessioninfo.LoginRefusalCode
}

// PolicyOutcome is a sign-in policy's decision.
type PolicyOutcome int

const (
	// DenySignIn refuses the sign-in; SignInDecision.Refusal says why. Zero value. The
	// policy's own writes in its transaction are committed (for example an audit row).
	DenySignIn PolicyOutcome = iota
	// AllowSignIn establishes the session.
	AllowSignIn
	// RequireMFA holds the sign-in as pending until the application completes its MFA
	// step and calls CompletePending. The pending identity names the account, including
	// one this sign-in provisioned.
	RequireMFA
)

// SignInDecision is a sign-in policy's answer, evaluated after the account is known
// and before any session is issued, for every sign-in method.
type SignInDecision struct {
	Outcome PolicyOutcome
	Refusal sessioninfo.LoginRefusalCode
}

// SpannerAccountResolver resolves an unlinked external identity (req.Identity) inside
// the account resolution transaction, the first of a sign-in's two. The transaction
// commits unless the resolver, OnProvisioned or the storage fails with an error: a
// RejectIdentity or RequireConfirmation answer commits the resolver's own writes and no
// session. On Spanner the transaction may be retried, so the resolver may run more than
// once for one sign-in and must not have side effects outside it.
type SpannerAccountResolver func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*Resolution, error)

// PostgresAccountResolver is the Postgres variant of SpannerAccountResolver.
type PostgresAccountResolver func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*Resolution, error)

// SpannerSignInPolicy decides a sign-in once req.UserID, req.Identity and req.Account
// are known, inside the transaction that then inserts the session. The account
// resolution has committed by then, so the policy reads the account and the rows the
// resolver and OnProvisioned wrote; req.Account says how the account was found
// (Provisioned() for one this sign-in created) and the link's tenant. The transaction
// commits unless the policy or the storage fails with an error: a DenySignIn or
// RequireMFA answer commits the policy's own writes and no session.
type SpannerSignInPolicy func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*SignInDecision, error)

// PostgresSignInPolicy is the Postgres variant of SpannerSignInPolicy.
type PostgresSignInPolicy func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*SignInDecision, error)

// SpannerIdentities is the validated identities configuration for Spanner storage.
type SpannerIdentities struct {
	tableName string
	resolve   SpannerAccountResolver
	policy    SpannerSignInPolicy
}

// NewSpannerIdentities builds the identities configuration: the identities table name,
// the account resolver (required) and the sign-in policy (nil means allow).
func NewSpannerIdentities(tableName string, resolve SpannerAccountResolver, policy SpannerSignInPolicy) (*SpannerIdentities, error) {
	if err := validateIdentities(tableName, resolve == nil); err != nil {
		return nil, err
	}

	return &SpannerIdentities{tableName: tableName, resolve: resolve, policy: policy}, nil
}

// PostgresIdentities is the validated identities configuration for Postgres storage.
type PostgresIdentities struct {
	tableName string
	resolve   PostgresAccountResolver
	policy    PostgresSignInPolicy
}

// NewPostgresIdentities is the Postgres variant of NewSpannerIdentities.
func NewPostgresIdentities(tableName string, resolve PostgresAccountResolver, policy PostgresSignInPolicy) (*PostgresIdentities, error) {
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

// WithSpannerIdentities attaches an identities configuration to Spanner account storage.
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

// WithPostgresIdentities attaches an identities configuration to Postgres account storage.
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

// AccountStore is the storage behind an Auth session: accounts (SessionUsers),
// sessions with UserId, identity links, and auth events.
type AccountStore interface {
	PasswordAuthStore
	// Identity returns the link for (method, connection, subject), or a NotFound error.
	Identity(ctx context.Context, method sessioninfo.AuthMethod, connection, subject string) (*SessionIdentity, error)
	// IdentitiesByUser lists an account's identity links.
	IdentitiesByUser(ctx context.Context, userID ccc.UUID) ([]*SessionIdentity, error)
	// LinkIdentity links an identity to an account outside the sign-in flow (for
	// example after a pending confirmation).
	LinkIdentity(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*SessionIdentity, error)
	// UnlinkIdentity removes a link. It refuses to remove the last means of sign-in of
	// an account that has no password.
	UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error
	// DestroyUserSessions expires every session of an account, by UserId.
	DestroyUserSessions(ctx context.Context, userID ccc.UUID) error
	// AppendAuthEvent records a step-up or confirmation on an existing session.
	AppendAuthEvent(ctx context.Context, sessionID ccc.UUID, event sessioninfo.AuthEvent) error
	// IdentitiesEnabled reports whether an identities configuration is attached.
	IdentitiesEnabled() bool
}

var _ AccountStore = (*Accounts)(nil)

// Accounts is account storage for Auth sessions.
type Accounts struct {
	*PasswordAuth
}

// NewSpannerAccounts creates Spanner account storage.
func NewSpannerAccounts(client *cloudspanner.Client, opts ...SpannerOption) *Accounts {
	return &Accounts{PasswordAuth: NewSpannerPasswordAuth(client, append([]SpannerOption{accountsOption{}}, opts...)...)}
}

// NewPostgresAccounts creates Postgres account storage.
func NewPostgresAccounts(pg postgres.Queryer, opts ...PostgresOption) *Accounts {
	return &Accounts{PasswordAuth: NewPostgresPassword(pg, append([]PostgresOption{accountsOption{}}, opts...)...)}
}

// Identity implements AccountStore.
func (a *Accounts) Identity(ctx context.Context, method sessioninfo.AuthMethod, connection, subject string) (*SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	link, err := a.db.Identity(ctx, method, connection, subject)
	if err != nil {
		return nil, errors.Wrap(err, "db.Identity()")
	}

	return (*SessionIdentity)(link), nil
}

// IdentitiesByUser implements AccountStore.
func (a *Accounts) IdentitiesByUser(ctx context.Context, userID ccc.UUID) ([]*SessionIdentity, error) {
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

// LinkIdentity implements AccountStore.
func (a *Accounts) LinkIdentity(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	link, err := a.db.LinkIdentity(ctx, userID, identity, tenant)
	if err != nil {
		return nil, errors.Wrap(err, "db.LinkIdentity()")
	}

	return (*SessionIdentity)(link), nil
}

// UnlinkIdentity implements AccountStore.
func (a *Accounts) UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.UnlinkIdentity(ctx, identityID); err != nil {
		return errors.Wrap(err, "db.UnlinkIdentity()")
	}

	return nil
}

// DestroyUserSessions implements AccountStore.
func (a *Accounts) DestroyUserSessions(ctx context.Context, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "db.DestroyUserSessions()")
	}

	return nil
}

// AppendAuthEvent implements AccountStore.
func (a *Accounts) AppendAuthEvent(ctx context.Context, sessionID ccc.UUID, event sessioninfo.AuthEvent) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.db.AppendAuthEvent(ctx, sessionID, &event); err != nil {
		return errors.Wrap(err, "db.AppendAuthEvent()")
	}

	return nil
}

// IdentitiesEnabled implements AccountStore.
func (a *Accounts) IdentitiesEnabled() bool {
	return a.db.IdentitiesEnabled()
}
