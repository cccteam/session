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
	config *SpannerCustomSessionData
}

func (o spannerCustomSessionDataOption) applySpanner(driver *spanner.SessionStorageDriver) {
	driver.SetCustomSessionData(o.config.driverConfig())
}

// WithSpannerCustomSessionData attaches a custom session data configuration
// (see NewSpannerCustomSessionData) to Spanner-backed storage. The configuration's
// resolver runs inside the session-insert transaction once per session creation, and
// a resolver error aborts the session creation; the decoder runs on every
// authenticated request and must tolerate all-nil raw maps (LEFT JOIN, no custom row).
func WithSpannerCustomSessionData(config *SpannerCustomSessionData) SpannerOption {
	return spannerCustomSessionDataOption{config: config}
}

type postgresCustomSessionDataOption struct {
	config *PostgresCustomSessionData
}

func (o postgresCustomSessionDataOption) applyPostgres(driver *postgres.SessionStorageDriver) {
	driver.SetCustomSessionData(o.config.driverConfig())
}

// WithPostgresCustomSessionData attaches a custom session data configuration
// (see NewPostgresCustomSessionData) to PostgreSQL-backed storage. The configuration's
// resolver runs inside the session-insert transaction once per session creation, and
// a resolver error aborts the session creation; the decoder runs on every
// authenticated request and must tolerate all-nil raw maps (LEFT JOIN, no custom row).
func WithPostgresCustomSessionData(config *PostgresCustomSessionData) PostgresOption {
	return postgresCustomSessionDataOption{config: config}
}
