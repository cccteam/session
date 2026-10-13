package sessionstorage

import (
	"context"
	"reflect"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// NewSessionResolver resolves the custom session data of a session being created,
// returning the row to store or nil for no row. It runs inside the transaction that
// inserts the session row, typed to the store's transaction (pgx.Tx or
// *spanner.ReadWriteTransaction), once per session creation (a sign-in, a confirmation,
// an MFA completion and a regeneration each create a session and resolve afresh), after
// the user resolution: req carries the user, a provisioned one included, and
// req.User says how it was found. An error aborts the transaction: no session is
// created.
type NewSessionResolver[T, Tx any] func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*T, error)

// CustomSessionData is the custom session data configuration of an Auth store over Tx:
// the table whose rows are T, keyed by the session, and the resolver that writes a
// session's row when the session is created. Build it with NewCustomSessionData and
// attach it with Auth.WithCustomSessionData; a configuration typed to the other
// driver's transaction does not compile there.
type CustomSessionData[T, Tx any] struct {
	tableName string
	codec     *dbtype.CustomDataCodec
	resolver  NewSessionResolver[T, Tx]
}

// NewCustomSessionData validates and builds the custom session data configuration for
// the struct type T over the store's transaction type Tx, both inferred from resolve.
// With a nil resolver, name them: NewCustomSessionData[MyData, pgx.Tx]("SessionCustomData", nil);
// session creation then performs a plain insert, and custom data comes from per-call
// values or UpdateCustomSessionData.
//
// Tx selects the driver and the struct tags that name T's columns: pgx.Tx reads `db:`
// tags, *spanner.ReadWriteTransaction `spanner:` tags (comma options ignored; an
// untagged exported field uses the field name; a tag of "-" skips the field). Fields
// whose columns can be NULL must use nullable Go types; a session with no custom data
// row yields a zero-value T.
//
// Requirements:
//   - The table MUST have a primary key column named "SessionId" that is a FK to the
//     session table's primary key with ON DELETE CASCADE.
//   - T must not map a field to "SessionId" (it is implied and reserved).
//
// See the "Custom session data" section of the README for the full lifecycle.
func NewCustomSessionData[T, Tx any](tableName string, resolve NewSessionResolver[T, Tx]) (*CustomSessionData[T, Tx], error) {
	tagKey, err := tagKeyFor[Tx]()
	if err != nil {
		return nil, err
	}
	codec, err := dbtype.NewCustomDataCodec(reflect.TypeFor[T](), tagKey)
	if err != nil {
		return nil, errors.Wrap(err, "dbtype.NewCustomDataCodec()")
	}
	if err := validateCustomSessionData(tableName, codec.Columns()); err != nil {
		return nil, err
	}

	return &CustomSessionData[T, Tx]{tableName: tableName, codec: codec, resolver: resolve}, nil
}

// TableName returns the custom session data table name.
func (c *CustomSessionData[T, Tx]) TableName() string {
	return c.tableName
}

// Columns returns the column names derived from T's tags (excluding "SessionId").
func (c *CustomSessionData[T, Tx]) Columns() []string {
	return c.codec.Columns()
}

// sessionData implements SessionDataConfig.
func (c *CustomSessionData[T, Tx]) sessionData() *customSessionData[Tx] {
	cfg := &customSessionData[Tx]{tableName: c.tableName, codec: c.codec}
	if c.resolver != nil {
		resolve := c.resolver
		cfg.resolver = func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (any, error) {
			data, err := resolve(ctx, tx, req)
			if err != nil {
				return nil, err
			}
			if data == nil {
				// Explicit conversion so a typed nil *T never crosses as a non-nil any.
				return nil, nil
			}

			return data, nil
		}
	}

	return cfg
}

// SessionDataConfig is a custom session data configuration typed to the store's
// transaction: a *CustomSessionData[T, Tx].
type SessionDataConfig[Tx any] interface {
	sessionData() *customSessionData[Tx]
}

// customSessionData is a configuration as the drivers take it, with T erased.
type customSessionData[Tx any] struct {
	tableName string
	codec     *dbtype.CustomDataCodec
	resolver  func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (any, error)
}

// CustomUserData is the custom user data configuration of an Auth store: the table whose
// rows are U, keyed by the user. Custom user data is durable: it lives and dies with the
// user record, untouched by logout, expiry and regeneration, and is read on demand,
// never joined into the per-request session read. It is written per call on
// CreateSessionUser and by UpdateCustomUserData, or by the user resolver's
// signin.Provision hook; there is no login hook. Build it with NewCustomUserData and
// attach it with Auth.WithCustomUserData. It fits either driver: columns derive from
// U's `db:` tags on PostgreSQL and its `spanner:` tags on Spanner.
type CustomUserData[U any] struct {
	tableName string
	codecs    map[string]*dbtype.CustomDataCodec
}

// NewCustomUserData validates and builds the custom user data configuration for the
// struct type U: NewCustomUserData[UserData]("UserCustomData").
//
// Columns derive from U's `db:` tags on PostgreSQL and `spanner:` tags on Spanner
// (comma options ignored; an untagged exported field uses the field name; a tag of "-"
// skips the field); both derivations are validated here. Fields whose columns can be
// NULL must use nullable Go types; a user with no custom data row yields a zero-value U.
//
// Requirements:
//   - The table MUST have a primary key column named "UserId" that is a FK to
//     SessionUsers.Id with ON DELETE CASCADE.
//   - U must not map a field to "UserId" (it is implied and reserved).
//
// See the "Custom user data" section of the README for the full lifecycle.
func NewCustomUserData[U any](tableName string) (*CustomUserData[U], error) {
	codecs := make(map[string]*dbtype.CustomDataCodec, 2)
	for _, tagKey := range []string{dbtype.PostgresTagKey, dbtype.SpannerTagKey} {
		codec, err := dbtype.NewCustomDataCodec(reflect.TypeFor[U](), tagKey)
		if err != nil {
			return nil, errors.Wrap(err, "dbtype.NewCustomDataCodec()")
		}
		if err := validateCustomUserData(tableName, codec.Columns()); err != nil {
			return nil, errors.Wrapf(err, "%s tags", tagKey)
		}
		codecs[tagKey] = codec
	}

	return &CustomUserData[U]{tableName: tableName, codecs: codecs}, nil
}

// TableName returns the custom user data table name.
func (c *CustomUserData[U]) TableName() string {
	return c.tableName
}

// userData implements UserDataConfig.
func (c *CustomUserData[U]) userData(tagKey string) (tableName string, codec *dbtype.CustomDataCodec) {
	return c.tableName, c.codecs[tagKey]
}

// UserDataConfig is a custom user data configuration: a *CustomUserData[U].
type UserDataConfig interface {
	userData(tagKey string) (tableName string, codec *dbtype.CustomDataCodec)
}

// tagKeyFor returns the struct tag key of the driver whose transaction type is Tx.
func tagKeyFor[Tx any]() (string, error) {
	switch reflect.TypeFor[Tx]() {
	case reflect.TypeFor[pgx.Tx]():
		return dbtype.PostgresTagKey, nil
	case reflect.TypeFor[*cloudspanner.ReadWriteTransaction]():
		return dbtype.SpannerTagKey, nil
	default:
		return "", errors.Newf("the transaction type %v is neither pgx.Tx (NewPostgresAuth) nor *spanner.ReadWriteTransaction (NewSpannerAuth)", reflect.TypeFor[Tx]())
	}
}

// customDataAttacher attaches custom data configurations to one driver, typed to its
// transaction, so a resolver reaches the driver without a conversion.
type customDataAttacher[Tx any] interface {
	attachSessionData(c *customSessionData[Tx])
	attachUserData(cfg UserDataConfig)
}

type spannerCustomData struct {
	driver *spanner.SessionStorageDriver
}

func (s spannerCustomData) attachSessionData(c *customSessionData[*cloudspanner.ReadWriteTransaction]) {
	s.driver.SetCustomSessionData(&spanner.CustomSessionDataConfig{TableName: c.tableName, Codec: c.codec, Resolver: c.resolver})
}

func (s spannerCustomData) attachUserData(cfg UserDataConfig) {
	tableName, codec := cfg.userData(dbtype.SpannerTagKey)
	s.driver.SetCustomUserData(&spanner.CustomUserDataConfig{TableName: tableName, Codec: codec})
}

type postgresCustomData struct {
	driver *postgres.SessionStorageDriver
}

func (p postgresCustomData) attachSessionData(c *customSessionData[pgx.Tx]) {
	p.driver.SetCustomSessionData(&postgres.CustomSessionDataConfig{TableName: c.tableName, Codec: c.codec, Resolver: c.resolver})
}

func (p postgresCustomData) attachUserData(cfg UserDataConfig) {
	tableName, codec := cfg.userData(dbtype.PostgresTagKey)
	p.driver.SetCustomUserData(&postgres.CustomUserDataConfig{TableName: tableName, Codec: codec})
}

// WithCustomSessionData attaches cfg, the store's one custom session data
// configuration, and returns the store. cfg's resolver is typed to the store's
// transaction, so a configuration built for the other driver does not compile here.
// The resolver runs inside the session-insert transaction once per session creation,
// and its error aborts the session creation; rows are scanned into T on every
// authenticated request. A later call replaces the configuration.
func (a *Auth[Tx]) WithCustomSessionData(cfg SessionDataConfig[Tx]) *Auth[Tx] {
	a.custom.attachSessionData(cfg.sessionData())

	return a
}

// WithCustomUserData attaches cfg, the store's one custom user data configuration, and
// returns the store. Custom user data lives and dies with the user record and is read
// on demand. A later call replaces the configuration.
func (a *Auth[Tx]) WithCustomUserData(cfg UserDataConfig) *Auth[Tx] {
	a.custom.attachUserData(cfg)

	return a
}
