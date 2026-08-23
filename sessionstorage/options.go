package sessionstorage

import (
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
)

// SpannerOption configures Spanner-backed storage at construction.
type SpannerOption interface {
	applySpanner(driver *spanner.SessionStorageDriver)
}

// PostgresOption configures PostgreSQL-backed storage at construction.
type PostgresOption interface {
	applyPostgres(driver *postgres.SessionStorageDriver)
}

type spannerCustomSessionDataOption struct {
	config *spanner.CustomSessionDataConfig
}

func (o spannerCustomSessionDataOption) applySpanner(driver *spanner.SessionStorageDriver) {
	driver.SetCustomSessionData(o.config)
}

// WithSpannerCustomSessionData attaches a custom session data configuration
// (see NewSpannerCustomSessionData) to Spanner-backed storage. The configuration's
// resolver runs inside the session-insert transaction once per session creation, and
// a resolver error aborts the session creation; rows are scanned into T on every
// authenticated request (a session with no custom data row yields a zero-value T).
func WithSpannerCustomSessionData[T any](config *SpannerCustomSessionData[T]) SpannerOption {
	return spannerCustomSessionDataOption{config: config.driverConfig()}
}

type postgresCustomSessionDataOption struct {
	config *postgres.CustomSessionDataConfig
}

func (o postgresCustomSessionDataOption) applyPostgres(driver *postgres.SessionStorageDriver) {
	driver.SetCustomSessionData(o.config)
}

// WithPostgresCustomSessionData attaches a custom session data configuration
// (see NewPostgresCustomSessionData) to PostgreSQL-backed storage. The configuration's
// resolver runs inside the session-insert transaction once per session creation, and
// a resolver error aborts the session creation; rows are scanned into T on every
// authenticated request (a session with no custom data row yields a zero-value T).
func WithPostgresCustomSessionData[T any](config *PostgresCustomSessionData[T]) PostgresOption {
	return postgresCustomSessionDataOption{config: config.driverConfig()}
}

type spannerCustomUserDataOption struct {
	config *spanner.CustomUserDataConfig
}

func (o spannerCustomUserDataOption) applySpanner(driver *spanner.SessionStorageDriver) {
	driver.SetCustomUserData(o.config)
}

// WithSpannerCustomUserData attaches a custom user data configuration (see
// NewSpannerCustomUserData) to Spanner-backed storage. Custom user data lives and dies
// with the user record and is read on demand — it never enters the per-request session
// read. For OIDC storage it requires the OIDC user anchor (WithOIDCUsers).
func WithSpannerCustomUserData[U any](config *SpannerCustomUserData[U]) SpannerOption {
	return spannerCustomUserDataOption{config: config.driverConfig()}
}

type postgresCustomUserDataOption struct {
	config *postgres.CustomUserDataConfig
}

func (o postgresCustomUserDataOption) applyPostgres(driver *postgres.SessionStorageDriver) {
	driver.SetCustomUserData(o.config)
}

// WithPostgresCustomUserData attaches a custom user data configuration (see
// NewPostgresCustomUserData) to PostgreSQL-backed storage. Custom user data lives and
// dies with the user record and is read on demand — it never enters the per-request
// session read. For OIDC storage it requires the OIDC user anchor (WithOIDCUsers).
func WithPostgresCustomUserData[U any](config *PostgresCustomUserData[U]) PostgresOption {
	return postgresCustomUserDataOption{config: config.driverConfig()}
}

// Option configures storage of either backend at construction.
type Option interface {
	SpannerOption
	PostgresOption
}

type oidcUsersOption struct{}

func (oidcUsersOption) applySpanner(driver *spanner.SessionStorageDriver)   { driver.EnableOIDCUsers() }
func (oidcUsersOption) applyPostgres(driver *postgres.SessionStorageDriver) { driver.EnableOIDCUsers() }

// WithOIDCUsers enables the library-managed OIDC user anchor: a durable user record
// (table "OIDCUsers" by default) keyed by the immutable (tid, oid) claim pair with a
// surrogate UUID primary key, provisioned and maintained just-in-time by an upsert
// inside every OIDC session-insert transaction. Username is a mutable attribute,
// updated in place at login, so an IdP rename never orphans the record. When enabled,
// NewSessionRequest.UserID carries the anchor record's ID into custom session data
// resolvers and custom user data hooks. It is required for custom user data on OIDC
// storage, and is OIDC-only. See the "OIDC user anchor" section of the README.
func WithOIDCUsers() Option {
	return oidcUsersOption{}
}
