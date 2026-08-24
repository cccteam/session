package spanner

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/spxscan"
	"github.com/cccteam/spxscan/spxapi"
	"github.com/go-playground/errors/v5"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
)

// CustomUserDataConfig configures the custom user data table for the Spanner driver.
// It is populated by the public sessionstorage package from a validated typed unit; the
// driver performs no validation of its own.
type CustomUserDataConfig struct {
	// TableName is the name of the custom user data table.
	TableName string
	// Codec maps the consumer's struct type U to its columns and provides the erased
	// value/scan operations. It is always non-nil.
	Codec *dbtype.CustomDataCodec
	// Hook, when non-nil, runs inside every OIDC session-insert transaction after the
	// OIDCUsers anchor upsert. current is *U for the existing row, or nil when the user
	// has no row yet. A nil return leaves the row untouched; a non-nil return is
	// upserted as the full row. It never runs outside OIDC session creation.
	Hook func(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest, current any) (any, error)
}

// SetCustomUserData attaches the custom user data configuration to the driver.
func (s *SessionStorageDriver) SetCustomUserData(config *CustomUserDataConfig) {
	s.customUserData = config
}

// CustomUserDataType returns the struct type the attached custom user data
// configuration was built for, or nil when no configuration is attached.
func (s *SessionStorageDriver) CustomUserDataType() reflect.Type {
	if s.customUserData == nil {
		return nil
	}

	return s.customUserData.Codec.StructType()
}

// UserDataLoginHookConfigured reports whether the attached custom user data
// configuration carries an OIDC login hook.
func (s *SessionStorageDriver) UserDataLoginHookConfigured() bool {
	return s.customUserData != nil && s.customUserData.Hook != nil
}

// EnableOIDCUsers enables the library-managed OIDCUsers anchor table, maintained by an
// upsert inside every OIDC session-insert transaction.
func (s *SessionStorageDriver) EnableOIDCUsers() {
	s.oidcUsersEnabled = true
}

// OIDCUsersEnabled reports whether the OIDCUsers anchor table is enabled.
func (s *SessionStorageDriver) OIDCUsersEnabled() bool {
	return s.oidcUsersEnabled
}

// SetOIDCUserTableName sets the name of the OIDC user anchor table.
func (s *SessionStorageDriver) SetOIDCUserTableName(name string) {
	s.oidcUserTableName = name
}

// userDataParentTable returns the user table the custom user data table references:
// OIDCUsers when the anchor is enabled, the session user table otherwise.
func (s *SessionStorageDriver) userDataParentTable() string {
	if s.oidcUsersEnabled {
		return s.oidcUserTableName
	}

	return s.userTableName
}

// CustomUserData returns the custom user data row for the given user ID as *U. A user
// with no custom data row yields a zero-value *U.
func (s *SessionStorageDriver) CustomUserData(ctx context.Context, userID ccc.UUID) (any, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.customUserData == nil {
		return nil, errors.New("custom user data config is not set")
	}

	data := s.customUserData.Codec.NewStruct()

	row, err := s.spanner.Single().ReadRow(ctx, s.customUserData.TableName, spanner.Key{userID}, s.customUserData.Codec.Columns())
	switch {
	case err == nil:
		if err := row.ToStruct(data); err != nil {
			return nil, errors.Wrap(err, "spanner.Row.ToStruct()")
		}
	case spanner.ErrCode(err) == codes.NotFound:
		// No custom user data row: zero-value *U.
	default:
		return nil, errors.Wrap(err, "spanner.ReadOnlyTransaction.ReadRow()")
	}

	return data, nil
}

// UpdateCustomUserData updates the custom user data for an existing user via a
// transactional read-modify-write: the current row is read (zero-value struct when no
// row exists), mutate is applied, and the full row is written back. The user's
// existence is verified inside the same transaction; a mutate error aborts the
// transaction with nothing written.
func (s *SessionStorageDriver) UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data any) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.customUserData == nil {
		return errors.New("custom user data config is not set")
	}

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		if _, err := txn.ReadRow(ctx, s.userDataParentTable(), spanner.Key{userID}, []string{"Id"}); err != nil {
			if spanner.ErrCode(err) == codes.NotFound {
				return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
			}

			return errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
		}

		data := s.customUserData.Codec.NewStruct()

		row, err := txn.ReadRow(ctx, s.customUserData.TableName, spanner.Key{userID}, s.customUserData.Codec.Columns())
		switch {
		case err == nil:
			if err := row.ToStruct(data); err != nil {
				return errors.Wrap(err, "spanner.Row.ToStruct()")
			}
		case spanner.ErrCode(err) == codes.NotFound:
			// No custom user data row yet: mutate receives the zero value and the
			// write below creates the row.
		default:
			return errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
		}

		if err := mutate(data); err != nil {
			return errors.Wrap(err, "custom user data mutate func")
		}

		m, err := customRowMutation(s.customUserData.TableName, s.customUserData.Codec, dbtype.UserIDColumn, userID, data, spanner.InsertOrUpdateMap)
		if err != nil {
			return err
		}
		if err := txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
			return errors.Wrap(err, "txn.BufferWrite()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// OIDCUser returns the OIDC user anchor record for the given ID.
func (s *SessionStorageDriver) OIDCUser(ctx context.Context, id ccc.UUID) (*dbtype.OIDCUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`
		SELECT
			Id,
			Tid,
			Oid,
			Username,
			CreatedAt,
			UpdatedAt
		FROM %s
		WHERE Id = @id
	`, s.oidcUserTableName))
	stmt.Params["id"] = id

	user := &dbtype.OIDCUser{}
	if err := spxscan.Get(ctx, s.spanner.Single(), user, stmt); err != nil {
		if errors.Is(err, spxapi.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("OIDC user id %q does not exist", id)
		}

		return nil, errors.Wrap(err, "spxscan.Get()")
	}

	return user, nil
}

// OIDCUserByKey returns the OIDC user anchor record for the given (tid, oid) claim pair.
func (s *SessionStorageDriver) OIDCUserByKey(ctx context.Context, tid, oid string) (*dbtype.OIDCUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`
		SELECT
			Id,
			Tid,
			Oid,
			Username,
			CreatedAt,
			UpdatedAt
		FROM %s
		WHERE Tid = @tid AND Oid = @oid
	`, s.oidcUserTableName))
	stmt.Params["tid"] = tid
	stmt.Params["oid"] = oid

	user := &dbtype.OIDCUser{}
	if err := spxscan.Get(ctx, s.spanner.Single(), user, stmt); err != nil {
		if errors.Is(err, spxapi.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("OIDC user (tid %q, oid %q) does not exist", tid, oid)
		}

		return nil, errors.Wrap(err, "spxscan.Get()")
	}

	return user, nil
}

// upsertOIDCUser resolves the OIDCUsers anchor row for the request's (Tid, Oid) inside
// txn — provisioning it on first login, updating Username in place on rename, touching
// UpdatedAt otherwise — and populates req.UserID with the anchor record's ID.
func (s *SessionStorageDriver) upsertOIDCUser(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) error {
	if req.Tid == "" || req.Oid == "" {
		return errors.New("the OIDC user anchor is enabled but the verified claims are missing the tid or oid claim")
	}

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT Id FROM %s WHERE Tid = @tid AND Oid = @oid`, s.oidcUserTableName))
	stmt.Params["tid"] = req.Tid
	stmt.Params["oid"] = req.Oid

	iter := txn.Query(ctx, stmt)
	defer iter.Stop()

	now := time.Now()

	row, err := iter.Next()
	if err != nil {
		if !errors.Is(err, iterator.Done) {
			return errors.Wrap(err, "spanner.RowIterator.Next()")
		}

		// First login for this (Tid, Oid): provision the anchor row.
		id, err := ccc.NewUUID()
		if err != nil {
			return errors.Wrap(err, "ccc.NewUUID()")
		}

		user := &dbtype.OIDCUser{
			ID:        id,
			Tid:       req.Tid,
			Oid:       req.Oid,
			Username:  req.Username,
			CreatedAt: now,
			UpdatedAt: now,
		}
		m, err := spanner.InsertStruct(s.oidcUserTableName, user)
		if err != nil {
			return errors.Wrap(err, "spanner.InsertStruct()")
		}
		if err := txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
			return errors.Wrap(err, "txn.BufferWrite()")
		}
		req.UserID = id

		return nil
	}

	var id ccc.UUID
	if err := row.Column(0, &id); err != nil {
		return errors.Wrap(err, "spanner.Row.Column()")
	}

	// Username is a mutable attribute: write the token's current value in place so an
	// IdP rename never orphans the record.
	update := struct {
		ID        ccc.UUID  `spanner:"Id"`
		Username  string    `spanner:"Username"`
		UpdatedAt time.Time `spanner:"UpdatedAt"`
	}{
		ID:        id,
		Username:  req.Username,
		UpdatedAt: now,
	}
	m, err := spanner.UpdateStruct(s.oidcUserTableName, update)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}
	if err := txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
		return errors.Wrap(err, "txn.BufferWrite()")
	}
	req.UserID = id

	return nil
}

// applyOIDCUserDataHook runs the configured custom user data login hook inside txn,
// feeding it the user's current row (nil when none), and buffers a full-row upsert when
// the hook returns a row. It requires req.UserID to be populated (see upsertOIDCUser).
func (s *SessionStorageDriver) applyOIDCUserDataHook(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) error {
	if s.customUserData == nil || s.customUserData.Hook == nil {
		return nil
	}

	var current any
	row, err := txn.ReadRow(ctx, s.customUserData.TableName, spanner.Key{req.UserID}, s.customUserData.Codec.Columns())
	switch {
	case err == nil:
		data := s.customUserData.Codec.NewStruct()
		if err := row.ToStruct(data); err != nil {
			return errors.Wrap(err, "spanner.Row.ToStruct()")
		}
		current = data
	case spanner.ErrCode(err) == codes.NotFound:
		// First login for this user: the hook receives nil.
	default:
		return errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
	}

	data, err := s.customUserData.Hook(ctx, txn, req, current)
	if err != nil {
		return errors.Wrap(err, "CustomUserDataConfig.Hook()")
	}
	if data == nil {
		return nil
	}

	m, err := customRowMutation(s.customUserData.TableName, s.customUserData.Codec, dbtype.UserIDColumn, req.UserID, data, spanner.InsertOrUpdateMap)
	if err != nil {
		return err
	}
	if err := txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
		return errors.Wrap(err, "txn.BufferWrite()")
	}

	return nil
}
