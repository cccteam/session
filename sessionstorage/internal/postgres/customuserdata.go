package postgres

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// CustomUserDataConfig configures the custom user data table for the PostgreSQL driver.
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
	Hook func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest, current any) (any, error)
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

	rows, err := s.conn.Query(ctx, s.customUserDataQuery(""), userID)
	if err != nil {
		return nil, errors.Wrap(err, "Queryer.Query()")
	}
	defer rows.Close()

	if rows.Next() {
		fieldAddrs, err := s.customUserData.Codec.FieldAddrs(data)
		if err != nil {
			return nil, errors.Wrap(err, "dbtype.CustomDataCodec.FieldAddrs()")
		}
		if err := rows.Scan(fieldAddrs...); err != nil {
			return nil, errors.Wrap(err, "pgx.Rows.Scan()")
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "pgx.Rows.Err()")
	}

	return data, nil
}

// UpdateCustomUserData updates the custom user data for an existing user via a
// transactional read-modify-write: the current row is read FOR UPDATE (zero-value
// struct when no row exists), mutate is applied, and the full row is written back. The
// user's existence is verified inside the same transaction; a mutate error aborts the
// transaction with nothing written.
func (s *SessionStorageDriver) UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data any) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.customUserData == nil {
		return errors.New("custom user data config is not set")
	}

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	existsQuery := fmt.Sprintf(`SELECT 1 FROM %s WHERE "Id" = $1 FOR UPDATE`, pgx.Identifier{s.userDataParentTable()}.Sanitize())
	var one int
	if err := txn.QueryRow(ctx, existsQuery, userID).Scan(&one); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
		}

		return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}

	data := s.customUserData.Codec.NewStruct()

	rows, err := txn.Query(ctx, s.customUserDataQuery(" FOR UPDATE"), userID)
	if err != nil {
		return errors.Wrap(err, "pgx.Tx.Query()")
	}
	if rows.Next() {
		fieldAddrs, err := s.customUserData.Codec.FieldAddrs(data)
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
		return errors.Wrap(err, "custom user data mutate func")
	}

	if err := insertCustomRow(ctx, txn, s.customUserData.TableName, s.customUserData.Codec, dbtype.UserIDColumn, userID, data, true); err != nil {
		return err
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "tx.Commit()")
	}

	return nil
}

// customUserDataQuery builds the custom user data row select, with suffix appended
// (e.g. " FOR UPDATE").
func (s *SessionStorageDriver) customUserDataQuery(suffix string) string {
	columns := s.customUserData.Codec.Columns()
	selectCols := make([]string, len(columns))
	for i, col := range columns {
		selectCols[i] = pgx.Identifier{col}.Sanitize()
	}

	return fmt.Sprintf(`SELECT %s FROM %s WHERE %s = $1%s`,
		strings.Join(selectCols, ", "),
		pgx.Identifier{s.customUserData.TableName}.Sanitize(),
		pgx.Identifier{dbtype.UserIDColumn}.Sanitize(),
		suffix,
	)
}

// OIDCUser returns the OIDC user anchor record for the given ID.
func (s *SessionStorageDriver) OIDCUser(ctx context.Context, id ccc.UUID) (*dbtype.OIDCUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		SELECT
			"Id",
			"Tid",
			"Oid",
			"Username",
			"CreatedAt",
			"UpdatedAt"
		FROM %s
		WHERE "Id" = $1
	`, pgx.Identifier{s.oidcUserTableName}.Sanitize())

	user := &dbtype.OIDCUser{}
	if err := pgxscan.Get(ctx, s.conn, user, query, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("OIDC user id %q does not exist", id)
		}

		return nil, errors.Wrap(err, "pgxscan.Get()")
	}

	return user, nil
}

// OIDCUserByKey returns the OIDC user anchor record for the given (tid, oid) claim pair.
func (s *SessionStorageDriver) OIDCUserByKey(ctx context.Context, tid, oid string) (*dbtype.OIDCUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		SELECT
			"Id",
			"Tid",
			"Oid",
			"Username",
			"CreatedAt",
			"UpdatedAt"
		FROM %s
		WHERE "Tid" = $1 AND "Oid" = $2
	`, pgx.Identifier{s.oidcUserTableName}.Sanitize())

	user := &dbtype.OIDCUser{}
	if err := pgxscan.Get(ctx, s.conn, user, query, tid, oid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("OIDC user (tid %q, oid %q) does not exist", tid, oid)
		}

		return nil, errors.Wrap(err, "pgxscan.Get()")
	}

	return user, nil
}

// upsertOIDCUser resolves the OIDCUsers anchor row for the request's (Tid, Oid) inside
// txn — provisioning it on first login, updating Username in place on rename, touching
// UpdatedAt otherwise — and populates req.UserID with the anchor record's ID.
func (s *SessionStorageDriver) upsertOIDCUser(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) error {
	if req.Tid == "" || req.Oid == "" {
		return errors.New("the OIDC user anchor is enabled but the verified claims are missing the tid or oid claim")
	}

	table := pgx.Identifier{s.oidcUserTableName}.Sanitize()
	now := time.Now()

	selectQuery := fmt.Sprintf(`SELECT "Id" FROM %s WHERE "Tid" = $1 AND "Oid" = $2 FOR UPDATE`, table)

	var id ccc.UUID
	err := txn.QueryRow(ctx, selectQuery, req.Tid, req.Oid).Scan(&id)
	switch {
	case err == nil:
		// Username is a mutable attribute: write the token's current value in place so
		// an IdP rename never orphans the record.
		updateQuery := fmt.Sprintf(`UPDATE %s SET "Username" = $2, "UpdatedAt" = $3 WHERE "Id" = $1`, table)
		if _, err := txn.Exec(ctx, updateQuery, id, req.Username, now); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}
	case errors.Is(err, pgx.ErrNoRows):
		// First login for this (Tid, Oid): provision the anchor row.
		id, err = ccc.NewUUID()
		if err != nil {
			return errors.Wrap(err, "ccc.NewUUID()")
		}

		insertQuery := fmt.Sprintf(`
			INSERT INTO %s
				("Id", "Tid", "Oid", "Username", "CreatedAt", "UpdatedAt")
			VALUES
				($1, $2, $3, $4, $5, $6)
			`, table)
		if _, err := txn.Exec(ctx, insertQuery, id, req.Tid, req.Oid, req.Username, now, now); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}
	default:
		return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}

	req.UserID = id

	return nil
}

// applyOIDCUserDataHook runs the configured custom user data login hook inside txn,
// feeding it the user's current row (nil when none), and writes a full-row upsert when
// the hook returns a row. It requires req.UserID to be populated (see upsertOIDCUser).
func (s *SessionStorageDriver) applyOIDCUserDataHook(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) error {
	if s.customUserData == nil || s.customUserData.Hook == nil {
		return nil
	}

	var current any
	rows, err := txn.Query(ctx, s.customUserDataQuery(" FOR UPDATE"), req.UserID)
	if err != nil {
		return errors.Wrap(err, "pgx.Tx.Query()")
	}
	if rows.Next() {
		data := s.customUserData.Codec.NewStruct()
		fieldAddrs, err := s.customUserData.Codec.FieldAddrs(data)
		if err != nil {
			rows.Close()

			return errors.Wrap(err, "dbtype.CustomDataCodec.FieldAddrs()")
		}
		if err := rows.Scan(fieldAddrs...); err != nil {
			rows.Close()

			return errors.Wrap(err, "pgx.Rows.Scan()")
		}
		current = data
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return errors.Wrap(err, "pgx.Rows.Err()")
	}

	data, err := s.customUserData.Hook(ctx, txn, req, current)
	if err != nil {
		return errors.Wrap(err, "CustomUserDataConfig.Hook()")
	}
	if data == nil {
		return nil
	}

	return insertCustomRow(ctx, txn, s.customUserData.TableName, s.customUserData.Codec, dbtype.UserIDColumn, req.UserID, data, true)
}
