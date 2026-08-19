package sessionstorage

import (
	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
)

var _ PreauthStore = (*Preauth)(nil)

// Preauth is the session storage implementation for Preauth.
type Preauth struct {
	sessionStorage
}

// NewSpannerPreauth is the function that you use to create the session manager that handles the session creation and updates
func NewSpannerPreauth(db *cloudspanner.Client, opts ...SpannerOption) *Preauth {
	driver := spanner.NewSessionStorageDriver(db)
	for _, opt := range opts {
		opt.applySpanner(driver)
	}

	return &Preauth{
		sessionStorage: sessionStorage{
			db: driver,
		},
	}
}

// NewPostgresPreauth is the function that you use to create the session manager that handles the session creation and updates
func NewPostgresPreauth(db postgres.Queryer, opts ...PostgresOption) *Preauth {
	driver := postgres.NewSessionStorageDriver(db)
	for _, opt := range opts {
		opt.applyPostgres(driver)
	}

	return &Preauth{
		sessionStorage: sessionStorage{
			db: driver,
		},
	}
}
