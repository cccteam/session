// Package spanner provides the session storage driver for Spanner.
package spanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
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

// SessionStorageDriver represents the session storage implementation for Spanner.
type SessionStorageDriver struct {
	spanner          *spanner.Client
	sessionTableName string
	userTableName    string
	// oidcUserTableName names the OIDC user anchor table for the driver's provider:
	// OIDCUsers (Azure) or GoogleOIDCUsers (Google). A driver serves exactly one
	// provider, fixed at construction.
	oidcUserTableName string
	oidcUsersEnabled  bool
	googleOIDC        bool
	customData        *CustomSessionDataConfig
	customUserData    *CustomUserDataConfig
	impersonation     *ImpersonationConfig
}

// expiredColumnName is the session table's Expired column.
const expiredColumnName = "Expired"

// NewSessionStorageDriver creates a new SessionStorageDriver
func NewSessionStorageDriver(client *spanner.Client) *SessionStorageDriver {
	return &SessionStorageDriver{
		spanner:           client,
		sessionTableName:  "Sessions",
		userTableName:     "SessionUsers",
		oidcUserTableName: "OIDCUsers",
	}
}

// NewGoogleSessionStorageDriver creates a SessionStorageDriver whose OIDC provider is
// Google: the user anchor is the Sub-keyed GoogleOIDCUsers table and sessions are
// inserted without an OidcSid (Google issues no sid claim).
func NewGoogleSessionStorageDriver(client *spanner.Client) *SessionStorageDriver {
	return &SessionStorageDriver{
		spanner:           client,
		sessionTableName:  "Sessions",
		userTableName:     "SessionUsers",
		oidcUserTableName: "GoogleOIDCUsers",
		googleOIDC:        true,
	}
}

// SetSessionTableName sets the name of the session table.
func (s *SessionStorageDriver) SetSessionTableName(name string) {
	s.sessionTableName = name
}

// SetUserTableName sets the name of the user table.
func (s *SessionStorageDriver) SetUserTableName(name string) {
	s.userTableName = name
}

// Session returns the session information from the database for given sessionID
func (s *SessionStorageDriver) Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.SessionData, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	qryStmt := s.sessionQuery(sessionID)
	iter := s.spanner.Single().Query(ctx, qryStmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err != nil {
		if errors.Is(err, iterator.Done) {
			return nil, httpio.NewNotFoundMessagef("session %q not found", sessionID)
		}

		return nil, errors.Wrap(err, "spanner.RowIterator.Next()")
	}

	session := &dbtype.Session{}

	// Use positional column access (row.Column) instead of row.ColumnByName b/c the JOIN may produce duplicate column names
	idx := 0
	baseDests := []struct {
		name string
		dest any
	}{
		{"Id", &session.ID},
		{"Username", &session.Username},
		{"CreatedAt", &session.CreatedAt},
		{"UpdatedAt", &session.UpdatedAt},
		{expiredColumnName, &session.Expired},
	}
	for _, col := range baseDests {
		if err := row.Column(idx, col.dest); err != nil {
			return nil, errors.Wrapf(err, "row.Column(%d/%s)", idx, col.name)
		}
		idx++
	}

	sessData := &dbtype.SessionData{Session: session}

	if s.customData != nil {
		data, next, err := s.readCustomData(row, idx)
		if err != nil {
			return nil, err
		}
		sessData.CustomData = data
		idx = next
	}

	if s.impersonation != nil {
		imp, err := readImpersonation(row, idx, session.ID)
		if err != nil {
			return nil, err
		}
		sessData.Impersonation = imp
	}

	return sessData, nil
}

// readCustomData reads the custom session data row from row positionally,
// starting at the marker column idx, and returns the *T (zero-value when the
// LEFT JOIN found no row) together with the index of the next unread column.
func (s *SessionStorageDriver) readCustomData(row *spanner.Row, idx int) (data any, next int, err error) {
	// The query selects c.SessionId ahead of the custom columns as a row-presence
	// marker: a LEFT JOIN with no custom row yields NULL here.
	var marker spanner.NullString
	if err := row.Column(idx, &marker); err != nil {
		return nil, idx, errors.Wrapf(err, "row.Column(%d/%s)", idx, dbtype.SessionIDColumn)
	}
	idx++

	columns := s.customData.Codec.Columns()
	if !marker.Valid {
		// No custom data row: zero-value *T.
		return s.customData.Codec.NewStruct(), idx + len(columns), nil
	}

	values := make([]any, len(columns))
	for i, col := range columns {
		var val spanner.GenericColumnValue
		if err := row.Column(idx, &val); err != nil {
			return nil, idx, errors.Wrapf(err, "row.Column(%d/%s)", idx, col)
		}
		values[i] = val
		idx++
	}

	// Rebuild a row containing only the custom columns (names are unique within
	// the custom set) so the client's tag-based ToStruct can decode into T —
	// the JOIN row itself may contain duplicate column names.
	synthetic, err := spanner.NewRow(columns, values)
	if err != nil {
		return nil, idx, errors.Wrap(err, "spanner.NewRow()")
	}

	data = s.customData.Codec.NewStruct()
	if err := synthetic.ToStruct(data); err != nil {
		return nil, idx, errors.Wrap(err, "spanner.Row.ToStruct()")
	}

	return data, idx, nil
}

// UpdateSessionActivity updates the session activity column with the current time
func (s *SessionStorageDriver) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	sessionUpdate := struct {
		ID        ccc.UUID  `spanner:"Id"`
		UpdatedAt time.Time `spanner:"UpdatedAt"`
	}{
		ID:        sessionID,
		UpdatedAt: time.Now(),
	}

	mutation, err := spanner.UpdateStruct(s.sessionTableName, sessionUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return httpio.NewNotFoundMessagef("session %q not found", sessionUpdate.ID)
		}

		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// InsertSession inserts a Session into the database and returns its id. When the
// request carries caller-supplied custom data it is written atomically with the session
// insert and the configured resolver is not invoked. Otherwise, when a custom session
// data configuration with a resolver is attached, the resolver runs within the same
// read-write transaction as the session insert; a resolver error aborts the insert.
func (s *SessionStorageDriver) InsertSession(ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	session := &struct {
		ID ccc.UUID
		*dbtype.InsertSession
	}{
		ID:            id,
		InsertSession: insertSession,
	}

	sessionMutation, err := spanner.InsertStruct(s.sessionTableName, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.InsertStruct()")
	}

	if err := s.applySessionInsert(ctx, id, []*spanner.Mutation{sessionMutation}, req); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}

// applySessionInsert commits the session-insert mutations (the session row and any
// rows that must land with it), honoring the request's custom session data semantics:
// per-call data wins and is committed with the session mutations in a single Apply
// (the configured resolver is not invoked); otherwise a configured resolver runs
// within a read-write transaction; otherwise the session mutations are applied alone.
func (s *SessionStorageDriver) applySessionInsert(ctx context.Context, id ccc.UUID, sessionMutations []*spanner.Mutation, req *sessioninfo.NewSessionRequest) error {
	if req.CustomData != nil {
		if s.customData == nil {
			return errors.New("custom session data provided but no custom session data config is attached")
		}

		customMutation, err := s.customDataMutation(id, req.CustomData, spanner.InsertMap)
		if err != nil {
			return err
		}

		mutations := make([]*spanner.Mutation, 0, len(sessionMutations)+1)
		mutations = append(mutations, sessionMutations...)
		mutations = append(mutations, customMutation)
		if _, err := s.spanner.Apply(ctx, mutations); err != nil {
			return errors.Wrap(err, "spanner.Client.Apply()")
		}

		return nil
	}

	if s.customData == nil || s.customData.Resolver == nil {
		if _, err := s.spanner.Apply(ctx, sessionMutations); err != nil {
			return errors.Wrap(err, "spanner.Client.Apply()")
		}

		return nil
	}

	// Use a ReadWriteTransaction so the resolver can read within the same transaction.
	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		if err := txn.BufferWrite(sessionMutations); err != nil {
			return errors.Wrap(err, "txn.BufferWrite()")
		}

		data, err := s.customData.Resolver(ctx, txn, req)
		if err != nil {
			return errors.Wrap(err, "CustomSessionDataConfig.Resolver()")
		}

		if data != nil {
			m, err := s.customDataMutation(id, data, spanner.InsertMap)
			if err != nil {
				return err
			}
			if err := txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
				return errors.Wrap(err, "txn.BufferWrite()")
			}
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// customDataMutation builds a full-row mutation for the custom session data table from
// data (*T), using the given mutation constructor (InsertMap or InsertOrUpdateMap).
func (s *SessionStorageDriver) customDataMutation(id ccc.UUID, data any, newMutation func(string, map[string]any) *spanner.Mutation) (*spanner.Mutation, error) {
	return customRowMutation(s.customData.TableName, s.customData.Codec, dbtype.SessionIDColumn, id, data, newMutation)
}

// customRowMutation builds a full-row mutation for a custom data table from data (*T),
// keyed by keyColumn, using the given mutation constructor (InsertMap or InsertOrUpdateMap).
func customRowMutation(
	tableName string, codec *dbtype.CustomDataCodec, keyColumn string, key ccc.UUID, data any, newMutation func(string, map[string]any) *spanner.Mutation,
) (*spanner.Mutation, error) {
	values, err := codec.Values(data)
	if err != nil {
		return nil, errors.Wrap(err, "dbtype.CustomDataCodec.Values()")
	}

	columns := codec.Columns()
	row := make(map[string]any, len(columns)+1)
	row[keyColumn] = key
	for i, col := range columns {
		row[col] = values[i]
	}

	return newMutation(tableName, row), nil
}

// DestroySession marks the session as expired
func (s *SessionStorageDriver) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	sessionUpdate := struct {
		ID        ccc.UUID  `spanner:"Id"`
		Expired   bool      `spanner:"Expired"`
		UpdatedAt time.Time `spanner:"UpdatedAt"`
	}{
		ID:        sessionID,
		Expired:   true,
		UpdatedAt: time.Now(),
	}

	mutation, err := spanner.UpdateStruct(s.sessionTableName, sessionUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		// Attempting to destroy a session that does not exist is something that
		// can happen when a browser returns with old state. Erroring in this
		// case is extra noise, so we will ignore instead.
		if spanner.ErrCode(err) != codes.NotFound {
			return errors.Wrap(err, "spanner.Client.Apply()")
		}
	}

	return s.endImpersonationIfConfigured(ctx, sessionID, sessioninfo.ImpersonationEndedByLogout)
}

// User returns the user record associated with the user id
func (s *SessionStorageDriver) User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`
		SELECT
			Id,
			Username,
			PasswordHash,
			Disabled
		FROM %s
		WHERE Id = @id
	`, s.userTableName))
	stmt.Params["id"] = id

	user := &dbtype.SessionUser{}
	if err := spxscan.Get(ctx, s.spanner.Single(), user, stmt); err != nil {
		if errors.Is(err, spxapi.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("user id %q does not exist", id)
		}

		return nil, errors.Wrap(err, "spxscan.Get()")
	}

	return user, nil
}

// UserByUserName returns the user record associated with the username
func (s *SessionStorageDriver) UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`
		SELECT
			Id,
			Username,
			PasswordHash,
			Disabled
		FROM %s
		WHERE NormalizedUsername = NORMALIZE_AND_CASEFOLD(@username)
	`, s.userTableName))
	stmt.Params["username"] = username

	user := &dbtype.SessionUser{}
	if err := spxscan.Get(ctx, s.spanner.Single(), user, stmt); err != nil {
		if errors.Is(err, spxapi.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("username %q does not exist", username)
		}

		return nil, errors.Wrap(err, "spxscan.Get()")
	}

	return user, nil
}

// CreateUser creates a new user. When customData (*U, may be nil) is provided it is
// written to the custom user data table in the same commit as the user insert; it
// requires a custom user data configuration on the driver.
func (s *SessionStorageDriver) CreateUser(ctx context.Context, insertUser *dbtype.InsertSessionUser, customData any) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return nil, errors.Wrap(err, "ccc.NewUUID()")
	}

	user := &dbtype.SessionUser{
		ID:           id,
		Username:     insertUser.Username,
		PasswordHash: insertUser.PasswordHash,
		Disabled:     insertUser.Disabled,
	}

	mutation, err := spanner.InsertStruct(s.userTableName, user)
	if err != nil {
		return nil, errors.Wrap(err, "spanner.InsertStruct()")
	}

	mutations := []*spanner.Mutation{mutation}
	if customData != nil {
		if s.customUserData == nil {
			return nil, errors.New("custom user data provided but no custom user data config is attached")
		}

		customMutation, err := customRowMutation(s.customUserData.TableName, s.customUserData.Codec, dbtype.UserIDColumn, id, customData, spanner.InsertMap)
		if err != nil {
			return nil, err
		}
		mutations = append(mutations, customMutation)
	}

	if _, err := s.spanner.Apply(ctx, mutations); err != nil {
		if spanner.ErrCode(err) == codes.AlreadyExists && strings.Contains(err.Error(), "SessionUsersByNormalizedUsername") {
			return nil, httpio.NewConflictMessagef("username %q already exists", user.Username)
		}

		return nil, errors.Wrap(err, "spanner.Client.Apply()")
	}

	return user, nil
}

// SetUserUsername updates the user record and every active session row
// for that user atomically. The user's current Username is read inside the
// transaction so concurrent username changes cannot leave session rows stranded
// under a stale username.
func (s *SessionStorageDriver) SetUserUsername(ctx context.Context, userID ccc.UUID, newUsername string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	usernameUpdate := struct {
		ID       ccc.UUID `spanner:"Id"`
		Username string   `spanner:"Username"`
	}{
		ID:       userID,
		Username: newUsername,
	}

	mutation, err := spanner.UpdateStruct(s.userTableName, usernameUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	_, err = s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		row, err := txn.ReadRow(ctx, s.userTableName, spanner.Key{userID}, []string{"Username"})
		if err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
		}

		var oldUsername string
		if err := row.Column(0, &oldUsername); err != nil {
			return errors.Wrap(err, "spanner.Row.Column()")
		}

		if err := txn.BufferWrite([]*spanner.Mutation{mutation}); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.BufferWrite()")
		}

		// A live role-principal impersonation carrying this name belongs to the actor, not
		// to the renamed account, and keeps the name its record names.
		sessionsStmt := spanner.NewStatement(fmt.Sprintf(`
				UPDATE %s s
				SET Username = @newUsername, UpdatedAt = @updatedAt
				WHERE s.Username = @oldUsername AND s.Expired = FALSE AND NOT %s
		`, s.sessionTableName, s.liveRolePrincipalRecord()))
		sessionsStmt.Params["oldUsername"] = oldUsername
		sessionsStmt.Params["newUsername"] = newUsername
		sessionsStmt.Params["updatedAt"] = time.Now()

		if _, err := txn.Update(ctx, sessionsStmt); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}

		return nil
	})
	if err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
		}

		if spanner.ErrCode(err) == codes.AlreadyExists && strings.Contains(err.Error(), "SessionUsersByNormalizedUsername") {
			return httpio.NewConflictMessagef("username %q already exists", newUsername)
		}

		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// SetUserPasswordHash updates the user password hash
func (s *SessionStorageDriver) SetUserPasswordHash(ctx context.Context, userID ccc.UUID, hash *securehash.Hash) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	passwordUpdate := struct {
		ID           ccc.UUID         `spanner:"Id"`
		PasswordHash *securehash.Hash `spanner:"PasswordHash"`
	}{
		ID:           userID,
		PasswordHash: hash,
	}

	mutation, err := spanner.UpdateStruct(s.userTableName, passwordUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return httpio.NewNotFoundMessagef("user id %q does not exist", passwordUpdate.ID)
		}

		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// DeactivateUser deactivates a user
func (s *SessionStorageDriver) DeactivateUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	userUpdate := struct {
		ID       ccc.UUID `spanner:"Id"`
		Disabled bool     `spanner:"Disabled"`
	}{
		ID:       id,
		Disabled: true,
	}

	mutation, err := spanner.UpdateStruct(s.userTableName, userUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return httpio.NewNotFoundMessagef("user id %q does not exist", id)
		}

		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// DeleteUser deletes a user
func (s *SessionStorageDriver) DeleteUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`
			DELETE FROM %s
			WHERE Id = @id`, s.userTableName))
	stmt.Params["id"] = id

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		if deleteCount, err := txn.Update(ctx, stmt); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		} else if deleteCount == 0 {
			return httpio.NewNotFoundMessagef("user id %q does not exist", id)
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// ActivateUser activates a user
func (s *SessionStorageDriver) ActivateUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	userUpdate := struct {
		ID       ccc.UUID `spanner:"Id"`
		Disabled bool     `spanner:"Disabled"`
	}{
		ID:       id,
		Disabled: false,
	}

	mutation, err := spanner.UpdateStruct(s.userTableName, userUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return httpio.NewNotFoundMessagef("user id %q does not exist", id)
		}

		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// DestroyAllUserSessions destroys all sessions for a given user
func (s *SessionStorageDriver) DestroyAllUserSessions(ctx context.Context, username string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	now := time.Now()

	// A live role-principal impersonation carries the actor's name, not an account of
	// this user's, and is not one of their sessions.
	stmt := spanner.NewStatement(fmt.Sprintf(`
			UPDATE %s s
			SET Expired = TRUE, UpdatedAt = @updatedAt
			WHERE s.Username = @username AND NOT %s
	`, s.sessionTableName, s.liveRolePrincipalRecord()))
	stmt.Params["username"] = username
	stmt.Params["updatedAt"] = now

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		if s.impersonation != nil {
			// The user's live impersonation records end with the sessions, as Revoked.
			endRecords := spanner.NewStatement(fmt.Sprintf(`
					UPDATE %s
					SET EndedAt = @now, EndReason = @reason
					WHERE EndedAt IS NULL AND PrincipalKind <> '%s' AND SessionId IN (
						SELECT Id FROM %s WHERE Username = @username
					)
			`, s.impersonation.TableName, dbtype.PrincipalKindRole, s.sessionTableName))
			endRecords.Params["username"] = username
			endRecords.Params["now"] = now
			endRecords.Params["reason"] = string(sessioninfo.ImpersonationEndedByRevocation)
			if _, err := txn.Update(ctx, endRecords); err != nil {
				return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
			}
		}

		if _, err := txn.Update(ctx, stmt); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// UpdateCustomSessionData updates the custom session data for the given session via a
// transactional read-modify-write: the current row is read (zero-value struct when no
// row exists), mutate is applied, and the full row is written back. The session's
// existence and non-expiry are verified inside the same transaction; a mutate error
// aborts the transaction with nothing written.
func (s *SessionStorageDriver) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data any) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.customData == nil {
		return errors.New("custom session data config is not set")
	}

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		sessionRow, err := txn.ReadRow(ctx, s.sessionTableName, spanner.Key{sessionID}, []string{expiredColumnName})
		if err != nil {
			if spanner.ErrCode(err) == codes.NotFound {
				return httpio.NewNotFoundMessagef("session %q not found", sessionID)
			}

			return errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
		}
		var expired bool
		if err := sessionRow.Column(0, &expired); err != nil {
			return errors.Wrap(err, "spanner.Row.Column()")
		}
		if expired {
			return httpio.NewBadRequestMessage("cannot update custom session data for an expired session")
		}

		data := s.customData.Codec.NewStruct()

		row, err := txn.ReadRow(ctx, s.customData.TableName, spanner.Key{sessionID}, s.customData.Codec.Columns())
		switch {
		case err == nil:
			if err := row.ToStruct(data); err != nil {
				return errors.Wrap(err, "spanner.Row.ToStruct()")
			}
		case spanner.ErrCode(err) == codes.NotFound:
			// No custom data row yet: mutate receives the zero value and the write
			// below creates the row.
		default:
			return errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
		}

		if err := mutate(data); err != nil {
			return errors.Wrap(err, "custom session data mutate func")
		}

		m, err := s.customDataMutation(sessionID, data, spanner.InsertOrUpdateMap)
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

func (s *SessionStorageDriver) sessionQuery(sessionID ccc.UUID) spanner.Statement {
	var columns strings.Builder
	columns.WriteString("s.Id, s.Username, s.CreatedAt, s.UpdatedAt, s.Expired")

	joinClause := ""
	if s.customData != nil {
		// c.SessionId is selected ahead of the custom columns as a row-presence
		// marker for the LEFT JOIN (read positionally; the name never collides
		// because access is by index).
		fmt.Fprintf(&columns, ", c.%s", dbtype.SessionIDColumn)
		for _, col := range s.customData.Codec.Columns() {
			fmt.Fprintf(&columns, ", c.`%s`", col)
		}
		joinClause = fmt.Sprintf("LEFT JOIN `%s` c ON s.Id = c.%s", s.customData.TableName, dbtype.SessionIDColumn)
	}
	if s.impersonation != nil {
		// The impersonation record follows the custom columns, with its own
		// i.SessionId row-presence marker.
		columns.WriteString(impersonationSelect())
		joinClause += " " + s.impersonationJoin()
	}

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s s %s WHERE s.Id = @id`, columns.String(), s.sessionTableName, joinClause))
	stmt.Params["id"] = sessionID

	return stmt
}
