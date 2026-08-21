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
