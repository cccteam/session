// Package postgres implements the session storage driver for PostgreSQL.
package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SessionStorageDriver represents the session storage implementation for PostgreSQL.
type SessionStorageDriver struct {
	conn             Queryer
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

// NewSessionStorageDriver creates a new SessionStorageDriver
func NewSessionStorageDriver(conn Queryer) *SessionStorageDriver {
	return &SessionStorageDriver{
		conn:              conn,
		sessionTableName:  "Sessions",
		userTableName:     "SessionUsers",
		oidcUserTableName: "OIDCUsers",
	}
}

// NewGoogleSessionStorageDriver creates a SessionStorageDriver whose OIDC provider is
// Google: the user anchor is the Sub-keyed GoogleOIDCUsers table and sessions are
// inserted without an OidcSid (Google issues no sid claim).
func NewGoogleSessionStorageDriver(conn Queryer) *SessionStorageDriver {
	return &SessionStorageDriver{
		conn:              conn,
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

	query, args := s.sessionQuery(sessionID)
	rows, err := s.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "Queryer.Query()")
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, errors.Wrap(err, "rows.Err()")
		}

		return nil, httpio.NewNotFoundMessagef("session %q not found", sessionID)
	}

	session := &dbtype.Session{}
	baseDests := []any{&session.ID, &session.Username, &session.CreatedAt, &session.UpdatedAt, &session.Expired}

	if s.customData == nil && s.impersonation == nil {
		if err := rows.Scan(baseDests...); err != nil {
			return nil, errors.Wrap(err, "rows.Scan()")
		}

		return &dbtype.SessionData{Session: session}, nil
	}

	// Phase 1: scan base columns plus each joined row's SessionId row-presence
	// marker, with NULL-safe throwaway destinations for the joined columns.
	var customMarker, impMarker any
	if err := rows.Scan(s.markerScanDests(baseDests, &customMarker, &impMarker)...); err != nil {
		return nil, errors.Wrap(err, "rows.Scan()")
	}

	// Phase 2: re-scan the same buffered row, this time into typed destinations for
	// the joined rows that exist (pgx re-plans per destination, converting NULL-free
	// values into the typed fields); absent rows keep their throwaways.
	sessData := &dbtype.SessionData{Session: session}
	scanDests, impScan, err := s.typedScanDests(baseDests, sessData, customMarker, impMarker)
	if err != nil {
		return nil, err
	}
	if err := rows.Scan(scanDests...); err != nil {
		return nil, errors.Wrap(err, "rows.Scan()")
	}

	if impScan != nil {
		imp, err := impScan.row()
		if err != nil {
			return nil, err
		}
		sessData.Impersonation = imp
	}

	return sessData, nil
}

// markerScanDests returns the phase-one scan destinations: the base columns, then
// for each configured join its SessionId marker followed by throwaways.
func (s *SessionStorageDriver) markerScanDests(baseDests []any, customMarker, impMarker *any) []any {
	dests := make([]any, 0, len(baseDests)+2+len(impersonationColumns))
	dests = append(dests, baseDests...)
	if s.customData != nil {
		dests = append(dests, customMarker)
		dests = append(dests, throwaways(len(s.customData.Codec.Columns()))...)
	}
	if s.impersonation != nil {
		dests = append(dests, impMarker)
		dests = append(dests, throwaways(len(impersonationColumns))...)
	}

	return dests
}

// typedScanDests returns the phase-two scan destinations. It populates
// sessData.CustomData with the *T to scan into (zero-value when the join found no
// row, which then keeps throwaways) and returns the impersonation scan when the
// record's row exists.
func (s *SessionStorageDriver) typedScanDests(baseDests []any, sessData *dbtype.SessionData, customMarker, impMarker any) ([]any, *impersonationScan, error) {
	dests := make([]any, 0, len(baseDests)+2+len(impersonationColumns))
	dests = append(dests, baseDests...)
	if s.customData != nil {
		sessData.CustomData = s.customData.Codec.NewStruct()
		dests = append(dests, &customMarker)
		if customMarker == nil {
			dests = append(dests, throwaways(len(s.customData.Codec.Columns()))...)
		} else {
			fieldAddrs, err := s.customData.Codec.FieldAddrs(sessData.CustomData)
			if err != nil {
				return nil, nil, errors.Wrap(err, "dbtype.CustomDataCodec.FieldAddrs()")
			}
			dests = append(dests, fieldAddrs...)
		}
	}

	var impScan *impersonationScan
	if s.impersonation != nil {
		dests = append(dests, &impMarker)
		if impMarker == nil {
			dests = append(dests, throwaways(len(impersonationColumns))...)
		} else {
			impScan = newImpersonationScan(sessData.ID)
			dests = append(dests, impScan.dests()...)
		}
	}

	return dests, impScan, nil
}

// UpdateSessionActivity updates the session activity column with the current time
func (s *SessionStorageDriver) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "UpdatedAt" = $1
		WHERE "Id" = $2`, s.sessionTableName)

	res, err := s.conn.Exec(ctx, query, time.Now(), sessionID)
	if err != nil {
		return errors.Wrapf(err, "failed to update Sessions table for ID: %s", sessionID)
	}

	if cnt := res.RowsAffected(); cnt != 1 {
		return httpio.NewNotFoundMessagef("session %q not found", sessionID)
	}

	return nil
}

// InsertSession inserts a Session into the database and returns its id. When the
// request carries caller-supplied custom data it is written atomically with the session
// insert and the configured resolver is not invoked. Otherwise, when a custom session
// data configuration with a resolver is attached, the resolver runs within the same
// transaction as the session insert; a resolver error aborts the insert.
func (s *SessionStorageDriver) InsertSession(ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	query := fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5)
		`, s.sessionTableName)
	args := []any{id, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired}

	if err := s.execSessionInsert(ctx, id, query, args, req, nil); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}

// execSessionInsert executes a session-insert statement, honoring the request's custom
// session data semantics: per-call data wins and is written with the session insert in
// one transaction (the configured resolver is not invoked); otherwise a configured
// resolver runs within the same transaction; otherwise the insert executes alone.
// A non-nil companion runs inside the same transaction right after the session insert,
// for rows that must land with the session (an impersonation record).
func (s *SessionStorageDriver) execSessionInsert(
	ctx context.Context, id ccc.UUID, query string, args []any, req *sessioninfo.NewSessionRequest, companion func(ctx context.Context, txn pgx.Tx) error,
) error {
	perCallData := req.CustomData != nil
	if perCallData && s.customData == nil {
		return errors.New("custom session data provided but no custom session data config is attached")
	}

	if companion == nil && !perCallData && (s.customData == nil || s.customData.Resolver == nil) {
		if _, err := s.conn.Exec(ctx, query, args...); err != nil {
			return errors.Wrap(err, "Queryer.Exec()")
		}

		return nil
	}

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	if _, err := txn.Exec(ctx, query, args...); err != nil {
		return errors.Wrap(err, "tx.Exec()")
	}

	if companion != nil {
		if err := companion(ctx, txn); err != nil {
			return err
		}
	}

	data := req.CustomData
	if !perCallData && s.customData != nil && s.customData.Resolver != nil {
		data, err = s.customData.Resolver(ctx, txn, req)
		if err != nil {
			return errors.Wrap(err, "CustomSessionDataConfig.Resolver()")
		}
	}

	if data != nil {
		if err := s.insertCustomSessionData(ctx, txn, id, data, false); err != nil {
			return err
		}
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "tx.Commit()")
	}

	return nil
}

// DestroySession marks the session as expired
func (s *SessionStorageDriver) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "Expired" = TRUE, "UpdatedAt" = $2
		WHERE "Id" = $1`, s.sessionTableName)

	if _, err := s.conn.Exec(ctx, query, sessionID, time.Now()); err != nil {
		// Attempting to destroy a session that does not exist is something that
		// can happen when a browser returns with old state. Erroring in this
		// case is extra noise, so we will ignore instead.
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return s.endImpersonationIfConfigured(ctx, sessionID, sessioninfo.ImpersonationEndedByLogout)
}

// User returns the user record associated with the user id
func (s *SessionStorageDriver) User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		SELECT
			"Id", 
			"Username", 
			"PasswordHash", 
			"Disabled"
		FROM "%s"
		WHERE "Id" = $1
	`, s.userTableName)

	user := &dbtype.SessionUser{}
	if err := pgxscan.Get(ctx, s.conn, user, query, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("user id %q does not exist", id)
		}

		return nil, errors.Wrap(err, "pgxscan.Get()")
	}

	return user, nil
}

// UserByUserName returns the user record associated with the username
func (s *SessionStorageDriver) UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		SELECT
			"Id", 
			"Username", 
			"PasswordHash", 
			"Disabled"
		FROM "%s"
		WHERE "NormalizedUsername" = casefold(normalize($1))
	`, s.userTableName)

	user := &dbtype.SessionUser{}
	if err := pgxscan.Get(ctx, s.conn, user, query, username); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("username %q does not exist", username)
		}

		return nil, errors.Wrapf(err, "pgxscan.Get()")
	}

	return user, nil
}

// CreateUser creates a new user. When customData (*U, may be nil) is provided it is
// written to the custom user data table in the same transaction as the user insert; it
// requires a custom user data configuration on the driver.
func (s *SessionStorageDriver) CreateUser(ctx context.Context, user *dbtype.InsertSessionUser, customData any) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if customData != nil && s.customUserData == nil {
		return nil, errors.New("custom user data provided but no custom user data config is attached")
	}

	id, err := ccc.NewUUID()
	if err != nil {
		return nil, errors.Wrap(err, "ccc.NewUUID()")
	}

	query := fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "Username", "PasswordHash", "Disabled")
		VALUES
			($1, $2, $3, $4)
		`, s.userTableName)
	args := []any{id, user.Username, user.PasswordHash, user.Disabled}

	if err := s.execUserInsert(ctx, id, query, args, customData); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation && pgErr.ConstraintName == "SessionUsers_NormalizedUsername_idx" {
			return nil, httpio.NewConflictMessagef("username %q already exists", user.Username)
		}

		return nil, err
	}

	return s.User(ctx, id)
}

// execUserInsert executes a user-insert statement; when customData is non-nil the
// custom user data row is written in the same transaction.
func (s *SessionStorageDriver) execUserInsert(ctx context.Context, id ccc.UUID, query string, args []any, customData any) error {
	if customData == nil {
		if _, err := s.conn.Exec(ctx, query, args...); err != nil {
			return errors.Wrap(err, "Queryer.Exec()")
		}

		return nil
	}

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	if _, err := txn.Exec(ctx, query, args...); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	if err := insertCustomRow(ctx, txn, s.customUserData.TableName, s.customUserData.Codec, dbtype.UserIDColumn, id, customData, false); err != nil {
		return err
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "tx.Commit()")
	}

	return nil
}

// SetUserUsername updates the user record and every active session row
// for that user atomically. The user's current Username is read inside the transaction
// with a row lock so concurrent username changes cannot leave session rows stranded
// under a stale username.
func (s *SessionStorageDriver) SetUserUsername(ctx context.Context, userID ccc.UUID, newUsername string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	selectQuery := fmt.Sprintf(`
		SELECT "Username" FROM "%s"
		WHERE "Id" = $1
		FOR UPDATE`, s.userTableName)

	var oldUsername string
	if err := tx.QueryRow(ctx, selectQuery, userID).Scan(&oldUsername); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
		}

		return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}

	userQuery := fmt.Sprintf(`
		UPDATE "%s" SET "Username" = $2
		WHERE "Id" = $1`, s.userTableName)

	if _, err := tx.Exec(ctx, userQuery, userID, newUsername); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation && pgErr.ConstraintName == "SessionUsers_NormalizedUsername_idx" {
			return httpio.NewConflictMessagef("username %q already exists", newUsername)
		}

		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	sessionQuery := fmt.Sprintf(`
		UPDATE "%s" SET "Username" = $2, "UpdatedAt" = $3
		WHERE "Username" = $1 AND "Expired" = FALSE`, s.sessionTableName)

	if _, err := tx.Exec(ctx, sessionQuery, oldUsername, newUsername, time.Now()); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	if err := tx.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}

// SetUserPasswordHash updates the user password hash
func (s *SessionStorageDriver) SetUserPasswordHash(ctx context.Context, userID ccc.UUID, hash *securehash.Hash) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "PasswordHash" = $2
		WHERE "Id" = $1`, s.userTableName)

	if cmdTag, err := s.conn.Exec(ctx, query, userID, hash); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	} else if cmdTag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
	}

	return nil
}

// DeactivateUser deactivates a user
func (s *SessionStorageDriver) DeactivateUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "Disabled" = TRUE
		WHERE "Id" = $1`, s.userTableName)

	if cmdTag, err := s.conn.Exec(ctx, query, id); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	} else if cmdTag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", id)
	}

	return nil
}

// DeleteUser deletes a user
func (s *SessionStorageDriver) DeleteUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		DELETE FROM "%s"
		WHERE "Id" = $1`, s.userTableName)

	if cmdTag, err := s.conn.Exec(ctx, query, id); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	} else if cmdTag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", id)
	}

	return nil
}

// ActivateUser activates a user
func (s *SessionStorageDriver) ActivateUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "Disabled" = FALSE
		WHERE "Id" = $1`, s.userTableName)

	if cmdTag, err := s.conn.Exec(ctx, query, id); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	} else if cmdTag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", id)
	}

	return nil
}

// DestroyAllUserSessions destroys all sessions for a given user
func (s *SessionStorageDriver) DestroyAllUserSessions(ctx context.Context, username string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s"
		SET "Expired" = TRUE, "UpdatedAt" = $2
		WHERE "Username" = $1`, s.sessionTableName)

	if s.impersonation == nil {
		if _, err := s.conn.Exec(ctx, query, username, time.Now()); err != nil {
			return errors.Wrap(err, "Queryer.Exec()")
		}

		return nil
	}

	// The user's live impersonation records end with the sessions, as Revoked.
	endRecords := fmt.Sprintf(`
		UPDATE %s i
		SET "EndedAt" = $2, "EndReason" = $3
		FROM "%s" s
		WHERE s."Id" = i."SessionId" AND s."Username" = $1 AND i."EndedAt" IS NULL`, pgx.Identifier{s.impersonation.TableName}.Sanitize(), s.sessionTableName)

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	now := time.Now()
	if _, err := txn.Exec(ctx, endRecords, username, now, string(sessioninfo.ImpersonationEndedByRevocation)); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}
	if _, err := txn.Exec(ctx, query, username, now); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}

// UpdateCustomSessionData updates the custom session data for an active session via a
// transactional read-modify-write: the current row is read FOR UPDATE (zero-value
// struct when no row exists), mutate is applied, and the full row is written back. The
// session's existence and non-expiry are verified inside the same transaction; a mutate
// error aborts the transaction with nothing written.
func (s *SessionStorageDriver) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data any) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.customData == nil {
		return errors.New("custom session data config is not set")
	}

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	sessionQuery := fmt.Sprintf(`SELECT "Expired" FROM %s WHERE "Id" = $1 FOR UPDATE`, pgx.Identifier{s.sessionTableName}.Sanitize())
	var expired bool
	if err := txn.QueryRow(ctx, sessionQuery, sessionID).Scan(&expired); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpio.NewNotFoundMessagef("session %q not found", sessionID)
		}

		return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}
	if expired {
		return httpio.NewBadRequestMessage("cannot update custom session data for an expired session")
	}

	columns := s.customData.Codec.Columns()
	selectCols := make([]string, len(columns))
	for i, col := range columns {
		selectCols[i] = pgx.Identifier{col}.Sanitize()
	}
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE %s = $1 FOR UPDATE`,
		strings.Join(selectCols, ", "),
		pgx.Identifier{s.customData.TableName}.Sanitize(),
		pgx.Identifier{dbtype.SessionIDColumn}.Sanitize(),
	)

	data := s.customData.Codec.NewStruct()

	rows, err := txn.Query(ctx, query, sessionID)
	if err != nil {
		return errors.Wrap(err, "pgx.Tx.Query()")
	}
	if rows.Next() {
		fieldAddrs, err := s.customData.Codec.FieldAddrs(data)
		if err != nil {
			rows.Close()

			return errors.Wrap(err, "dbtype.CustomDataCodec.FieldAddrs()")
		}
		if err := rows.Scan(fieldAddrs...); err != nil {
			rows.Close()

			return errors.Wrap(err, "pgx.Rows.Scan()")
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return errors.Wrap(err, "pgx.Rows.Err()")
	}

	if err := mutate(data); err != nil {
		return errors.Wrap(err, "custom session data mutate func")
	}

	if err := s.insertCustomSessionData(ctx, txn, sessionID, data, true); err != nil {
		return err
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "tx.Commit()")
	}

	return nil
}

func (s *SessionStorageDriver) sessionQuery(sessionID ccc.UUID) (query string, args []any) {
	var columns strings.Builder
	columns.WriteString(`s."Id", s."Username", s."CreatedAt", s."UpdatedAt", s."Expired"`)

	joinClause := ""
	if s.customData != nil {
		// c.SessionId is selected ahead of the custom columns as a row-presence
		// marker for the LEFT JOIN (read positionally).
		fmt.Fprintf(&columns, `, c.%s`, pgx.Identifier{dbtype.SessionIDColumn}.Sanitize())
		for _, col := range s.customData.Codec.Columns() {
			fmt.Fprintf(&columns, `, c.%s`, pgx.Identifier{col}.Sanitize())
		}
		joinClause = fmt.Sprintf(`LEFT JOIN %s c ON s."Id" = c.%s`, pgx.Identifier{s.customData.TableName}.Sanitize(), pgx.Identifier{dbtype.SessionIDColumn}.Sanitize())
	}
	if s.impersonation != nil {
		// The impersonation record follows the custom columns, with its own
		// i.SessionId row-presence marker.
		columns.WriteString(impersonationSelect())
		joinClause += " " + s.impersonationJoin()
	}

	query = fmt.Sprintf(`
			SELECT %s
			FROM "%s" s
			%s
			WHERE s."Id" = $1`,
		columns.String(), s.sessionTableName, joinClause)

	return query, []any{sessionID}
}

// insertCustomSessionData writes a full custom data row for data (*T) inside txn.
// When upsert is true an existing row is overwritten (ON CONFLICT DO UPDATE).
func (s *SessionStorageDriver) insertCustomSessionData(ctx context.Context, txn pgx.Tx, sessionID ccc.UUID, data any, upsert bool) error {
	return insertCustomRow(ctx, txn, s.customData.TableName, s.customData.Codec, dbtype.SessionIDColumn, sessionID, data, upsert)
}

// insertCustomRow writes a full custom data row for data (*T) inside txn, keyed by
// keyColumn. When upsert is true an existing row is overwritten (ON CONFLICT DO UPDATE).
func insertCustomRow(ctx context.Context, txn pgx.Tx, tableName string, codec *dbtype.CustomDataCodec, keyColumn string, key ccc.UUID, data any, upsert bool) error {
	values, err := codec.Values(data)
	if err != nil {
		return errors.Wrap(err, "dbtype.CustomDataCodec.Values()")
	}

	codecColumns := codec.Columns()
	columns := make([]string, 0, len(codecColumns)+1)
	columns = append(columns, pgx.Identifier{keyColumn}.Sanitize())
	args := make([]any, 0, len(values)+1)
	args = append(args, key)
	for i, col := range codecColumns {
		columns = append(columns, pgx.Identifier{col}.Sanitize())
		args = append(args, values[i])
	}

	placeholders := make([]string, len(args))
	for i := range args {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	conflictClause := ""
	if upsert {
		setClauses := make([]string, 0, len(codecColumns))
		for _, col := range columns[1:] {
			setClauses = append(setClauses, fmt.Sprintf("%s = EXCLUDED.%s", col, col))
		}
		conflictClause = fmt.Sprintf("ON CONFLICT (%s) DO UPDATE SET %s",
			pgx.Identifier{keyColumn}.Sanitize(), strings.Join(setClauses, ", "))
	}

	q := fmt.Sprintf(`
		INSERT INTO %s
			(%s)
		VALUES
			(%s)
		%s
	`, pgx.Identifier{tableName}.Sanitize(), strings.Join(columns, ", "), strings.Join(placeholders, ", "), conflictClause)

	if _, err := txn.Exec(ctx, q, args...); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	return nil
}
