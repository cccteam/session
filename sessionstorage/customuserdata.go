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

// SpannerOIDCUserDataHook maintains custom user data at OIDC login for Spanner-backed
// storage. It runs inside every OIDC session-insert transaction, after the OIDCUsers
// anchor upsert (req.UserID holds the anchor record's ID) and before any custom session
// data resolver. current is the user's existing row, or nil on their first login.
// Returning nil leaves the row untouched; returning a *U upserts it as the FULL row —
// start from current when refreshing individual fields, or app-written fields are
// zeroed. Returning an error aborts the login: no anchor change, no row, no session.
// The hook never runs outside OIDC session creation (password auth has no claims; its
// initial data is per-call on CreateSessionUser).
type SpannerOIDCUserDataHook[U any] func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest, current *U) (*U, error)

// PostgresOIDCUserDataHook maintains custom user data at OIDC login for
// PostgreSQL-backed storage. It runs inside every OIDC session-insert transaction,
// after the OIDCUsers anchor upsert (req.UserID holds the anchor record's ID) and
// before any custom session data resolver. current is the user's existing row, or nil
// on their first login. Returning nil leaves the row untouched; returning a *U upserts
// it as the FULL row — start from current when refreshing individual fields, or
// app-written fields are zeroed. Returning an error aborts the login: no anchor change,
// no row, no session. The hook never runs outside OIDC session creation (password auth
// has no claims; its initial data is per-call on CreateSessionUser).
type PostgresOIDCUserDataHook[U any] func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest, current *U) (*U, error)

// SpannerCustomUserData is the validated custom user data configuration for
// Spanner-backed storage. The table's columns derive from U's `spanner:` struct tags,
// reflected once at construction. Custom user data is durable — it lives and dies with
// the user record, untouched by logout, expiry, and session regeneration — and is read
// on demand, never joined into the per-request session read. Build it with
// NewSpannerCustomUserData and attach it via WithSpannerCustomUserData.
type SpannerCustomUserData[U any] struct {
	tableName string
	codec     *dbtype.CustomDataCodec
	hook      SpannerOIDCUserDataHook[U]
}

// NewSpannerCustomUserData validates and builds a Spanner custom user data
// configuration for the struct type U.
//
// Columns derive from U's `spanner:` tags (comma options ignored; untagged exported
// fields use the field name; a tag of "-" skips the field). Fields whose columns can be
// NULL must use nullable Go types (e.g. spanner.NullString, ccc.NullUUID); a user with
// no custom data row yields a zero-value U. The hook may be nil; it is OIDC-only (see
// SpannerOIDCUserDataHook) and rejected at construction of password-auth and preauth
// session types.
//
// Requirements:
//   - The table MUST have a primary key column named "UserId" that is a FK to the user
//     table's primary key (SessionUsers.Id, or OIDCUsers.Id when the OIDC user anchor
//     is enabled) with ON DELETE CASCADE.
//   - U must not map a field to "UserId" (it is implied and reserved).
//
// See the "Custom user data" section of the README for the full lifecycle.
func NewSpannerCustomUserData[U any](tableName string, hook SpannerOIDCUserDataHook[U]) (*SpannerCustomUserData[U], error) {
	codec, err := dbtype.NewCustomDataCodec(reflect.TypeFor[U](), dbtype.SpannerTagKey)
	if err != nil {
		return nil, errors.Wrap(err, "dbtype.NewCustomDataCodec()")
	}
	if err := validateCustomUserData(tableName, codec.Columns()); err != nil {
		return nil, err
	}

	return &SpannerCustomUserData[U]{
		tableName: tableName,
		codec:     codec,
		hook:      hook,
	}, nil
}

// TableName returns the custom user data table name.
func (c *SpannerCustomUserData[U]) TableName() string {
	return c.tableName
}

// Columns returns the column names derived from U's `spanner:` tags (excluding "UserId").
func (c *SpannerCustomUserData[U]) Columns() []string {
	return c.codec.Columns()
}

// driverConfig converts the unit into the internal Spanner driver configuration.
func (c *SpannerCustomUserData[U]) driverConfig() *spanner.CustomUserDataConfig {
	cfg := &spanner.CustomUserDataConfig{
		TableName: c.tableName,
		Codec:     c.codec,
	}
	if c.hook != nil {
		hook := c.hook
		cfg.Hook = func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest, current any) (any, error) {
			var cur *U
			if current != nil {
				typed, ok := current.(*U)
				if !ok {
					return nil, errors.Newf("custom user data type mismatch: storage decoded %T, hook expects %T", current, (*U)(nil))
				}
				cur = typed
			}

			data, err := hook(ctx, txn, req, cur)
			if err != nil {
				return nil, err
			}
			if data == nil {
				// Explicit conversion so a typed nil *U never crosses as a non-nil any.
				return nil, nil
			}

			return data, nil
		}
	}

	return cfg
}

// PostgresCustomUserData is the validated custom user data configuration for
// PostgreSQL-backed storage. The table's columns derive from U's `db:` struct tags,
// reflected once at construction. Custom user data is durable — it lives and dies with
// the user record, untouched by logout, expiry, and session regeneration — and is read
// on demand, never joined into the per-request session read. Build it with
// NewPostgresCustomUserData and attach it via WithPostgresCustomUserData.
type PostgresCustomUserData[U any] struct {
	tableName string
	codec     *dbtype.CustomDataCodec
	hook      PostgresOIDCUserDataHook[U]
}

// NewPostgresCustomUserData validates and builds a PostgreSQL custom user data
// configuration for the struct type U.
//
// Columns derive from U's `db:` tags (comma options ignored; untagged exported fields
// use the field name; a tag of "-" skips the field). Fields whose columns can be NULL
// must use nullable Go types (pointers or sql.Null types); a user with no custom data
// row yields a zero-value U. The hook may be nil; it is OIDC-only (see
// PostgresOIDCUserDataHook) and rejected at construction of password-auth and preauth
// session types.
//
// Requirements:
//   - The table MUST have a primary key column named "UserId" that is a FK to the user
//     table's primary key (SessionUsers.Id, or OIDCUsers.Id when the OIDC user anchor
//     is enabled) with ON DELETE CASCADE.
//   - U must not map a field to "UserId" (it is implied and reserved).
//
// See the "Custom user data" section of the README for the full lifecycle.
func NewPostgresCustomUserData[U any](tableName string, hook PostgresOIDCUserDataHook[U]) (*PostgresCustomUserData[U], error) {
	codec, err := dbtype.NewCustomDataCodec(reflect.TypeFor[U](), dbtype.PostgresTagKey)
	if err != nil {
		return nil, errors.Wrap(err, "dbtype.NewCustomDataCodec()")
	}
	if err := validateCustomUserData(tableName, codec.Columns()); err != nil {
		return nil, err
	}

	return &PostgresCustomUserData[U]{
		tableName: tableName,
		codec:     codec,
		hook:      hook,
	}, nil
}

// TableName returns the custom user data table name.
func (c *PostgresCustomUserData[U]) TableName() string {
	return c.tableName
}

// Columns returns the column names derived from U's `db:` tags (excluding "UserId").
func (c *PostgresCustomUserData[U]) Columns() []string {
	return c.codec.Columns()
}

// driverConfig converts the unit into the internal PostgreSQL driver configuration.
func (c *PostgresCustomUserData[U]) driverConfig() *postgres.CustomUserDataConfig {
	cfg := &postgres.CustomUserDataConfig{
		TableName: c.tableName,
		Codec:     c.codec,
	}
	if c.hook != nil {
		hook := c.hook
		cfg.Hook = func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest, current any) (any, error) {
			var cur *U
			if current != nil {
				typed, ok := current.(*U)
				if !ok {
					return nil, errors.Newf("custom user data type mismatch: storage decoded %T, hook expects %T", current, (*U)(nil))
				}
				cur = typed
			}

			data, err := hook(ctx, txn, req, cur)
			if err != nil {
				return nil, err
			}
			if data == nil {
				// Explicit conversion so a typed nil *U never crosses as a non-nil any.
				return nil, nil
			}

			return data, nil
		}
	}

	return cfg
}

// validateCustomUserData validates the table name and the tag-derived column names for
// a custom user data configuration.
func validateCustomUserData(tableName string, columns []string) error {
	if !validIdentifier.MatchString(tableName) {
		return errors.Newf("invalid table name: %s. Table names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", tableName)
	}

	for _, name := range columns {
		if !validIdentifier.MatchString(name) {
			return errors.Newf("invalid column name: %s. Column names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", name)
		}
		if dbtype.IsReservedCustomUserColumn(name) {
			return errors.Newf("invalid column name: %s. This column name is reserved and cannot be used as a custom user data column.", name)
		}
	}

	return nil
}
