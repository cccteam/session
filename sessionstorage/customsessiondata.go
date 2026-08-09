package sessionstorage

import (
	"context"
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
// Spanner-backed storage. It runs inside the same read-write transaction that inserts the
// session row, exactly once per session creation (login, external authentication, and
// session regeneration each create a session and re-resolve fresh). Returning an error
// aborts the transaction: no session is created and the login/session start fails.
type SpannerNewSessionResolver func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) ([]*sessioninfo.CustomData, error)

// PostgresNewSessionResolver resolves custom session data for a session being created in
// PostgreSQL-backed storage. It runs inside the same transaction that inserts the session
// row, exactly once per session creation (login, external authentication, and session
// regeneration each create a session and re-resolve fresh). Returning an error aborts the
// transaction: no session is created and the login/session start fails.
type PostgresNewSessionResolver func(ctx context.Context, txn pgx.Tx, req sessioninfo.NewSessionRequest) ([]*sessioninfo.CustomData, error)

// SpannerCustomSessionData is the validated custom session data configuration for
// Spanner-backed storage: the table, its columns, the decoder for reads, and the
// new-session resolver for writes. Build it with NewSpannerCustomSessionData and attach
// it via WithSpannerCustomSessionData.
type SpannerCustomSessionData struct {
	tableName string
	columns   []string
	decoder   func(rawCustomData map[string]any) (any, error)
	resolver  SpannerNewSessionResolver
}

// NewSpannerCustomSessionData validates and builds a Spanner custom session data
// configuration.
//
// The type parameter T is the consumer's strongly typed struct; retrieve it per request
// via sessioninfo.CustomDataFromCtx[T](ctx). The decoder runs on every authenticated
// request and MUST tolerate a raw map whose values are all nil, which occurs when a
// session has no custom data row (the read is a LEFT JOIN). The resolver may be nil,
// in which case session creation performs a plain insert and no custom data row is
// written.
//
// Requirements:
//   - The table MUST have a primary key column named "SessionId" that is a FK to the
//     session table's primary key with ON DELETE CASCADE.
//   - Do NOT include "SessionId" in columns (it is implied and reserved).
func NewSpannerCustomSessionData[T any](tableName string, decoder func(map[string]any) (T, error), resolver SpannerNewSessionResolver, columns ...string) (*SpannerCustomSessionData, error) {
	dedupedColumns, err := validateCustomSessionData(tableName, decoder == nil, columns)
	if err != nil {
		return nil, err
	}

	return &SpannerCustomSessionData{
		tableName: tableName,
		columns:   dedupedColumns,
		decoder:   eraseDecoder(decoder),
		resolver:  resolver,
	}, nil
}

// TableName returns the custom session data table name.
func (c *SpannerCustomSessionData) TableName() string {
	return c.tableName
}

// Columns returns the validated, deduplicated custom column names (excluding "SessionId").
func (c *SpannerCustomSessionData) Columns() []string {
	return append([]string(nil), c.columns...)
}

// driverConfig converts the unit into the internal Spanner driver configuration.
func (c *SpannerCustomSessionData) driverConfig() *spanner.CustomSessionDataConfig {
	if c == nil {
		return nil
	}

	return &spanner.CustomSessionDataConfig{
		TableName: c.tableName,
		Columns:   c.columns,
		Decoder:   c.decoder,
		// Direct assignment (not a closure) so a nil resolver stays nil.
		Resolver: c.resolver,
	}
}

// PostgresCustomSessionData is the validated custom session data configuration for
// PostgreSQL-backed storage: the table, its columns, the decoder for reads, and the
// new-session resolver for writes. Build it with NewPostgresCustomSessionData and attach
// it via WithPostgresCustomSessionData.
type PostgresCustomSessionData struct {
	tableName string
	columns   []string
	decoder   func(rawCustomData map[string]any) (any, error)
	resolver  PostgresNewSessionResolver
}

// NewPostgresCustomSessionData validates and builds a PostgreSQL custom session data
// configuration.
//
// The type parameter T is the consumer's strongly typed struct; retrieve it per request
// via sessioninfo.CustomDataFromCtx[T](ctx). The decoder runs on every authenticated
// request and MUST tolerate a raw map whose values are all nil, which occurs when a
// session has no custom data row (the read is a LEFT JOIN). The resolver may be nil,
// in which case session creation performs a plain insert and no custom data row is
// written.
//
// Requirements:
//   - The table MUST have a primary key column named "SessionId" that is a FK to the
//     session table's primary key with ON DELETE CASCADE.
//   - Do NOT include "SessionId" in columns (it is implied and reserved).
func NewPostgresCustomSessionData[T any](tableName string, decoder func(map[string]any) (T, error), resolver PostgresNewSessionResolver, columns ...string) (*PostgresCustomSessionData, error) {
	dedupedColumns, err := validateCustomSessionData(tableName, decoder == nil, columns)
	if err != nil {
		return nil, err
	}

	return &PostgresCustomSessionData{
		tableName: tableName,
		columns:   dedupedColumns,
		decoder:   eraseDecoder(decoder),
		resolver:  resolver,
	}, nil
}

// TableName returns the custom session data table name.
func (c *PostgresCustomSessionData) TableName() string {
	return c.tableName
}

// Columns returns the validated, deduplicated custom column names (excluding "SessionId").
func (c *PostgresCustomSessionData) Columns() []string {
	return append([]string(nil), c.columns...)
}

// driverConfig converts the unit into the internal PostgreSQL driver configuration.
func (c *PostgresCustomSessionData) driverConfig() *postgres.CustomSessionDataConfig {
	if c == nil {
		return nil
	}

	return &postgres.CustomSessionDataConfig{
		TableName: c.tableName,
		Columns:   c.columns,
		Decoder:   c.decoder,
		// Direct assignment (not a closure) so a nil resolver stays nil.
		Resolver: c.resolver,
	}
}

// eraseDecoder adapts a typed decoder to the untyped form stored in driver configs.
func eraseDecoder[T any](decoder func(map[string]any) (T, error)) func(map[string]any) (any, error) {
	return func(rawCustomData map[string]any) (any, error) {
		decoded, err := decoder(rawCustomData)
		if err != nil {
			return nil, err
		}

		return decoded, nil
	}
}

var validIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,127}$`)

// validateCustomSessionData validates the table name and column names for a custom
// session data configuration and returns the deduplicated column list.
func validateCustomSessionData(tableName string, nilDecoder bool, columns []string) ([]string, error) {
	if !validIdentifier.MatchString(tableName) {
		return nil, errors.Newf("invalid table name: %s. Table names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", tableName)
	}

	if nilDecoder {
		return nil, errors.New("decoder is required; to receive the raw column values, pass a decoder that returns its map argument unchanged")
	}

	seen := make(map[string]struct{}, len(columns))
	dedupedColumns := make([]string, 0, len(columns))
	for _, name := range columns {
		if !validIdentifier.MatchString(name) {
			return nil, errors.Newf("invalid column name: %s. Column names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", name)
		}
		if dbtype.IsReservedCustomColumn(name) {
			return nil, errors.Newf("invalid column name: %s. This column name is reserved and cannot be used as a custom session data column.", name)
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		dedupedColumns = append(dedupedColumns, name)
	}

	return dedupedColumns, nil
}
