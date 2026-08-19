package spanner

import (
	"context"
	"reflect"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
)

// CustomSessionDataConfig configures the custom session data table for the Spanner driver.
// It is populated by the public sessionstorage package from a validated typed unit; the
// driver performs no validation of its own.
type CustomSessionDataConfig struct {
	// TableName is the name of the custom session data table.
	TableName string
	// Codec maps the consumer's struct type T to its columns and provides the erased
	// value/scan operations. It is always non-nil.
	Codec *dbtype.CustomDataCodec
	// Resolver resolves custom session data inside the session-insert transaction,
	// returning *T (or nil for no row). When the Resolver field is nil, session
	// creation performs a plain insert with no custom data row.
	Resolver func(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (any, error)
}

// SetCustomSessionData attaches the custom session data configuration to the driver.
func (s *SessionStorageDriver) SetCustomSessionData(config *CustomSessionDataConfig) {
	s.customData = config
}

// CustomDataType returns the struct type the attached configuration was built for, or
// nil when no configuration is attached.
func (s *SessionStorageDriver) CustomDataType() reflect.Type {
	if s.customData == nil {
		return nil
	}

	return s.customData.Codec.StructType()
}
