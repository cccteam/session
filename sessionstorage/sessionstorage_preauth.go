package sessionstorage

import (
	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
)

var _ PreauthImplementation = (*Preauth)(nil)

// Preauth is the session storage implementation for Preauth.
type Preauth struct {
	sessionStorage
}

// NewSpannerPreauth is the function that you use to create the session manager that handles the session creation and updates
func NewSpannerPreauth(db *cloudspanner.Client) *Preauth {
	return &Preauth{
		sessionStorage: sessionStorage{
			db: spanner.NewSessionStorageDriver(db),
		},
	}
}

// NewPostgresPreauth is the function that you use to create the session manager that handles the session creation and updates
func NewPostgresPreauth(db postgres.Queryer) *Preauth {
	return &Preauth{
		sessionStorage: sessionStorage{
			db: postgres.NewSessionStorageDriver(db),
		},
	}
}
