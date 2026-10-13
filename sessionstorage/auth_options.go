package sessionstorage

import (
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
)

// authOption enables the session columns of the auth schema (Sessions.UserId
// and AuthenticatedAt). Only the Auth storage constructors apply it, so the legacy
// stores keep working on a session table without those columns.
type authOption struct{}

func (authOption) applySpanner(driver *spanner.SessionStorageDriver)   { driver.EnableAuth() }
func (authOption) applyPostgres(driver *postgres.SessionStorageDriver) { driver.EnableAuth() }
