package sessionstorage

import (
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
)

// accountsOption enables the session columns of the accounts schema (Sessions.UserId
// and AuthenticatedAt). Only the account storage constructors apply it, so the legacy
// stores keep working on a session table without those columns.
type accountsOption struct{}

func (accountsOption) applySpanner(driver *spanner.SessionStorageDriver)   { driver.EnableAccounts() }
func (accountsOption) applyPostgres(driver *postgres.SessionStorageDriver) { driver.EnableAccounts() }
