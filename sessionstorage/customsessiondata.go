package sessionstorage

import (
	"context"
	"reflect"
	"regexp"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// SpannerNewSessionResolver resolves custom session data for a session being created in
// Spanner-backed storage, returning the row to store (or nil for no row). It runs inside
// the same read-write transaction that inserts the session row, exactly once per session
// creation (login, external authentication, and session regeneration each create a
// session and re-resolve fresh). Returning an error aborts the transaction: no session
// is created and the login/session start fails.
type SpannerNewSessionResolver[T any] func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*T, error)

// PostgresNewSessionResolver resolves custom session data for a session being created in
// PostgreSQL-backed storage, returning the row to store (or nil for no row). It runs
// inside the same transaction that inserts the session row, exactly once per session
// creation (login, external authentication, and session regeneration each create a
// session and re-resolve fresh). Returning an error aborts the transaction: no session
// is created and the login/session start fails.
type PostgresNewSessionResolver[T any] func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*T, error)

// SpannerCustomSessionData is the validated custom session data configuration for
// Spanner-backed storage. The table's columns derive from T's `spanner:` struct tags,
// reflected once at construction; rows are scanned into T on every authenticated
// request. Build it with NewSpannerCustomSessionData and attach it via
// WithSpannerCustomSessionData.
type SpannerCustomSessionData[T any] struct {
	tableName string
	codec     *dbtype.CustomDataCodec
	resolver  SpannerNewSessionResolver[T]
}

// NewSpannerCustomSessionData validates and builds a Spanner custom session data
// configuration for the struct type T.
//
// Columns derive from T's `spanner:` tags (comma options ignored; untagged exported
// fields use the field name; a tag of "-" skips the field). Fields whose columns can be
// NULL must use nullable Go types (e.g. spanner.NullString, ccc.NullUUID); a session
// with no custom data row yields a zero-value T. The resolver may be nil, in which case
// session creation performs a plain insert and no custom data row is written.
//
// Requirements:
//   - The table MUST have a primary key column named "SessionId" that is a FK to the
//     session table's primary key with ON DELETE CASCADE.
//   - T must not map a field to "SessionId" (it is implied and reserved).
//
// See the "Custom session data" section of the README for the full lifecycle.
func NewSpannerCustomSessionData[T any](tableName string, resolver SpannerNewSessionResolver[T]) (*SpannerCustomSessionData[T], error) {
	codec, err := dbtype.NewCustomDataCodec(reflect.TypeFor[T](), dbtype.SpannerTagKey)
	if err != nil {
		return nil, errors.Wrap(err, "dbtype.NewCustomDataCodec()")
	}
	if err := validateCustomSessionData(tableName, codec.Columns()); err != nil {
		return nil, err
	}

	return &SpannerCustomSessionData[T]{
		tableName: tableName,
		codec:     codec,
		resolver:  resolver,
	}, nil
}

// TableName returns the custom session data table name.
func (c *SpannerCustomSessionData[T]) TableName() string {
	return c.tableName
}

// Columns returns the column names derived from T's `spanner:` tags (excluding "SessionId").
func (c *SpannerCustomSessionData[T]) Columns() []string {
	return c.codec.Columns()
}

// driverConfig converts the unit into the internal Spanner driver configuration.
func (c *SpannerCustomSessionData[T]) driverConfig() *spanner.CustomSessionDataConfig {
	cfg := &spanner.CustomSessionDataConfig{
		TableName: c.tableName,
		Codec:     c.codec,
	}
	if c.resolver != nil {
		resolver := c.resolver
		cfg.Resolver = func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (any, error) {
			data, err := resolver(ctx, txn, req)
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

// PostgresCustomSessionData is the validated custom session data configuration for
// PostgreSQL-backed storage. The table's columns derive from T's `db:` struct tags,
// reflected once at construction; rows are scanned into T on every authenticated
// request. Build it with NewPostgresCustomSessionData and attach it via
// WithPostgresCustomSessionData.
type PostgresCustomSessionData[T any] struct {
	tableName string
	codec     *dbtype.CustomDataCodec
	resolver  PostgresNewSessionResolver[T]
}

// NewPostgresCustomSessionData validates and builds a PostgreSQL custom session data
// configuration for the struct type T.
//
// Columns derive from T's `db:` tags (comma options ignored; untagged exported fields
// use the field name; a tag of "-" skips the field). Fields whose columns can be NULL
// must use nullable Go types (pointers or sql.Null types); a session with no custom
// data row yields a zero-value T. The resolver may be nil, in which case session
// creation performs a plain insert and no custom data row is written.
//
// Requirements:
//   - The table MUST have a primary key column named "SessionId" that is a FK to the
//     session table's primary key with ON DELETE CASCADE.
//   - T must not map a field to "SessionId" (it is implied and reserved).
//
// See the "Custom session data" section of the README for the full lifecycle.
func NewPostgresCustomSessionData[T any](tableName string, resolver PostgresNewSessionResolver[T]) (*PostgresCustomSessionData[T], error) {
	codec, err := dbtype.NewCustomDataCodec(reflect.TypeFor[T](), dbtype.PostgresTagKey)
	if err != nil {
		return nil, errors.Wrap(err, "dbtype.NewCustomDataCodec()")
	}
	if err := validateCustomSessionData(tableName, codec.Columns()); err != nil {
		return nil, err
	}

	return &PostgresCustomSessionData[T]{
		tableName: tableName,
		codec:     codec,
		resolver:  resolver,
	}, nil
}

// TableName returns the custom session data table name.
func (c *PostgresCustomSessionData[T]) TableName() string {
	return c.tableName
}

// Columns returns the column names derived from T's `db:` tags (excluding "SessionId").
func (c *PostgresCustomSessionData[T]) Columns() []string {
	return c.codec.Columns()
}

// driverConfig converts the unit into the internal PostgreSQL driver configuration.
func (c *PostgresCustomSessionData[T]) driverConfig() *postgres.CustomSessionDataConfig {
	cfg := &postgres.CustomSessionDataConfig{
		TableName: c.tableName,
		Codec:     c.codec,
	}
	if c.resolver != nil {
		resolver := c.resolver
		cfg.Resolver = func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (any, error) {
			data, err := resolver(ctx, txn, req)
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

var validIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,127}$`)

// validateCustomSessionData validates the table name and the tag-derived column names
// for a custom session data configuration.
func validateCustomSessionData(tableName string, columns []string) error {
	if !validIdentifier.MatchString(tableName) {
		return errors.Newf("invalid table name: %s. Table names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", tableName)
	}

	for _, name := range columns {
		if !validIdentifier.MatchString(name) {
			return errors.Newf("invalid column name: %s. Column names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", name)
		}
		if dbtype.IsReservedCustomColumn(name) {
			return errors.Newf("invalid column name: %s. This column name is reserved and cannot be used as a custom session data column.", name)
		}
	}

	return nil
}
