package postgres

import (
	"context"

	"github.com/cccteam/session/sessioninfo"
	"github.com/jackc/pgx/v5"
)

// CustomSessionDataConfig configures the custom session data table for the PostgreSQL driver.
// It is populated by the public sessionstorage package from a validated
// PostgresCustomSessionData unit; the driver performs no validation of its own.
type CustomSessionDataConfig struct {
	// TableName is the name of the custom session data table.
	TableName string
	// Columns is the validated, deduplicated list of custom column names (excluding "SessionId").
	Columns []string
	// Decoder converts the raw column-value map read from the database into the
	// consumer's typed value. It is always non-nil.
	Decoder func(rawCustomData map[string]any) (any, error)
	// Resolver resolves custom session data inside the session-insert transaction.
	// When nil, session creation performs a plain insert with no custom data row.
	Resolver func(ctx context.Context, txn pgx.Tx, req sessioninfo.NewSessionRequest) ([]*sessioninfo.CustomData, error)
}

// SetCustomSessionData attaches the custom session data configuration to the driver.
func (s *SessionStorageDriver) SetCustomSessionData(config *CustomSessionDataConfig) {
	s.customData = config
}
