package sessionstorage

import (
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
)

// accountsOption enables the accounts schema's session columns (Sessions.UserId and
// AuthenticatedAt, shipped in schema/*/accounts/migrations). Account storage applies it
// itself; the legacy store constructors never name those columns, so a session table
// without them keeps working.
type accountsOption struct{}

func (accountsOption) applySpanner(driver *spanner.SessionStorageDriver)   { driver.EnableAccounts() }
func (accountsOption) applyPostgres(driver *postgres.SessionStorageDriver) { driver.EnableAccounts() }
