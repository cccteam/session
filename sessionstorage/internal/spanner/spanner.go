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
	customData       *CustomSessionDataConfig
}

// expiredColumnName is the session table's Expired column.
const expiredColumnName = "Expired"

// NewSessionStorageDriver creates a new SessionStorageDriver
func NewSessionStorageDriver(client *spanner.Client) *SessionStorageDriver {
	return &SessionStorageDriver{
		spanner:          client,
		sessionTableName: "Sessions",
		userTableName:    "SessionUsers",
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

	if s.customData != nil && len(s.customData.Columns) > 0 {
		rawCustomData := make(map[string]any, len(s.customData.Columns))
		for _, col := range s.customData.Columns {
			var val spanner.GenericColumnValue
			if err := row.Column(idx, &val); err != nil {
				return nil, errors.Wrapf(err, "row.Column(%d/%s)", idx, col)
			}
			rawCustomData[col] = val.Value.AsInterface()
			idx++
		}

		decoded, err := s.customData.Decoder(rawCustomData)
		if err != nil {
			return nil, errors.Wrap(err, "CustomSessionDataConfig.Decoder()")
		}
		sessData.CustomData = decoded
	}

	return sessData, nil
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
func (s *SessionStorageDriver) InsertSession(ctx context.Context, insertSession *dbtype.InsertSession, req sessioninfo.NewSessionRequest) (ccc.UUID, error) {
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

	// Per-call custom data wins: written atomically with the session insert in a
	// single commit; the configured resolver is not invoked.
	if len(req.CustomData) > 0 {
		if s.customData == nil {
			return ccc.NilUUID, errors.New("custom session data provided but no custom session data config is attached")
		}

		row := map[string]any{
			dbtype.SessionIDColumn: id,
		}
		for _, c := range req.CustomData {
			row[c.ColumnName] = c.Value
		}

		mutations := []*spanner.Mutation{sessionMutation, spanner.InsertMap(s.customData.TableName, row)}
		if _, err := s.spanner.Apply(ctx, mutations); err != nil {
			return ccc.NilUUID, errors.Wrap(err, "spanner.Client.Apply()")
		}

		return id, nil
	}

	if s.customData == nil || s.customData.Resolver == nil {
		if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{sessionMutation}); err != nil {
			return ccc.NilUUID, errors.Wrap(err, "spanner.Client.Apply()")
		}

		return id, nil
	}

	// Use a ReadWriteTransaction so the resolver can read within the same transaction.
	_, err = s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		if err := txn.BufferWrite([]*spanner.Mutation{sessionMutation}); err != nil {
			return errors.Wrap(err, "txn.BufferWrite()")
		}

		customData, err := s.customData.Resolver(ctx, txn, req)
		if err != nil {
			return errors.Wrap(err, "CustomSessionDataConfig.Resolver()")
		}

		if len(customData) > 0 {
			row := map[string]any{
				dbtype.SessionIDColumn: id,
			}
			for _, c := range customData {
				row[c.ColumnName] = c.Value
			}

			m := spanner.InsertMap(s.customData.TableName, row)
			if err := txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
				return errors.Wrap(err, "txn.BufferWrite()")
			}
		}

		return nil
	})
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return id, nil
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

	return nil
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

// CreateUser creates a new user
func (s *SessionStorageDriver) CreateUser(ctx context.Context, insertUser *dbtype.InsertSessionUser) (*dbtype.SessionUser, error) {
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

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
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

		sessionsStmt := spanner.NewStatement(fmt.Sprintf(`
				UPDATE %s
				SET Username = @newUsername, UpdatedAt = @updatedAt
				WHERE Username = @oldUsername AND Expired = FALSE
		`, s.sessionTableName))
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

	stmt := spanner.NewStatement(fmt.Sprintf(`
			UPDATE %s
			SET Expired = TRUE, UpdatedAt = @updatedAt
			WHERE Username = @username
	`, s.sessionTableName))
	stmt.Params["username"] = username
	stmt.Params["updatedAt"] = time.Now()

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
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

// UpdateCustomSessionData updates the custom session data for the given session via an upsert on the custom session data table.
func (s *SessionStorageDriver) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, customData ...*sessioninfo.CustomData) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.customData == nil {
		return errors.New("custom session data config is not set")
	}

	if len(customData) == 0 {
		return nil
	}

	row := map[string]any{
		dbtype.SessionIDColumn: sessionID,
	}
	for _, c := range customData {
		row[c.ColumnName] = c.Value
	}

	m := spanner.InsertOrUpdateMap(s.customData.TableName, row)

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{m}); err != nil {
		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

func (s *SessionStorageDriver) sessionQuery(sessionID ccc.UUID) spanner.Statement {
	var columns strings.Builder
	columns.WriteString("s.Id, s.Username, s.CreatedAt, s.UpdatedAt, s.Expired")

	joinClause := ""
	if s.customData != nil && len(s.customData.Columns) > 0 {
		for _, col := range s.customData.Columns {
			fmt.Fprintf(&columns, ", c.`%s`", col)
		}
		joinClause = fmt.Sprintf("LEFT JOIN `%s` c ON s.Id = c.%s", s.customData.TableName, dbtype.SessionIDColumn)
	}

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s s %s WHERE s.Id = @id`, columns.String(), s.sessionTableName, joinClause))
	stmt.Params["id"] = sessionID

	return stmt
}
