package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/cccteam/ccc"
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

// The sign-in flow (internal/signinflow) drives the primitives below inside the
// transactions Transact opens; the SQL of a sign-in lives here, its sequence there.

// identityColumns are the identities table's columns.
const identityColumns = `"Id", "UserId", "Method", "Connection", "Subject", "Tenant", "EmailAtLink", "CreatedAt", "LastUsedAt"`

func (s *SessionStorageDriver) identitiesTable() string {
	return pgx.Identifier{s.identitiesTableName}.Sanitize()
}

// Transact runs fn in a transaction and commits when fn returns nil.
func (s *SessionStorageDriver) Transact(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) error {
	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	if err := fn(ctx, txn); err != nil {
		return err
	}
	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}

// SignInConflict classifies a unique violation a sign-in's transaction ended with: the
// user table's username index, or the identities table's key.
func (s *SessionStorageDriver) SignInConflict(err error) dbtype.SignInConflict {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return dbtype.NoSignInConflict
	}
	if pgErr.Code == pgerrcode.DeadlockDetected || pgErr.Code == pgerrcode.SerializationFailure {
		return dbtype.LockConflict
	}
	if pgErr.Code != pgerrcode.UniqueViolation {
		return dbtype.NoSignInConflict
	}

	switch {
	case pgErr.ConstraintName == s.usernameIndex():
		return dbtype.UsernameConflict
	case pgErr.TableName == s.identitiesTableName:
		return dbtype.IdentityConflict
	default:
		return dbtype.NoSignInConflict
	}
}

// IdentityIn returns the link for (method, connection, subject) inside tx, or nil.
func (s *SessionStorageDriver) IdentityIn(ctx context.Context, tx pgx.Tx, method sessioninfo.AuthMethod, connection, subject string) (*dbtype.SessionIdentity, error) {
	return s.lookupIdentity(ctx, tx, method, connection, subject)
}

// lookupIdentity returns the link for (method, connection, subject), or nil.
func (s *SessionStorageDriver) lookupIdentity(ctx context.Context, q pgxscan.Querier, method sessioninfo.AuthMethod, connection, subject string) (*dbtype.SessionIdentity, error) {
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "Method" = $1 AND "Connection" = $2 AND "Subject" = $3`, identityColumns, s.identitiesTable())

	var identities []*dbtype.SessionIdentity
	if err := pgxscan.Select(ctx, q, &identities, query, string(method), connection, subject); err != nil {
		return nil, errors.Wrap(err, "pgxscan.Select()")
	}
	if len(identities) == 0 {
		return nil, nil
	}

	return identities[0], nil
}

// TouchIdentityIn moves the link's LastUsedAt to now inside tx.
func (s *SessionStorageDriver) TouchIdentityIn(ctx context.Context, tx pgx.Tx, linkID ccc.UUID, now time.Time) error {
	touch := fmt.Sprintf(`UPDATE %s SET "LastUsedAt" = $2 WHERE "Id" = $1`, s.identitiesTable())
	if _, err := tx.Exec(ctx, touch, linkID, now); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	return nil
}

// LinkIdentityIn writes a new link of identity to userID inside tx.
func (s *SessionStorageDriver) LinkIdentityIn(
	ctx context.Context, tx pgx.Tx, userID ccc.UUID, identity *sessioninfo.Identity, tenant string, now time.Time,
) (*dbtype.SessionIdentity, error) {
	return s.insertLink(ctx, tx, userID, identity, tenant, now)
}

// insertLink writes a new link of identity to userID through q.
func (s *SessionStorageDriver) insertLink(
	ctx context.Context, q interface {
		Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	}, userID ccc.UUID, identity *sessioninfo.Identity, tenant string, now time.Time,
) (*dbtype.SessionIdentity, error) {
	if !dbtype.IsExternal(identity) || identity.Subject == "" {
		return nil, httpio.NewBadRequestMessage("only an external identity with a subject can be linked")
	}

	id, err := ccc.NewUUID()
	if err != nil {
		return nil, errors.Wrap(err, "ccc.NewUUID()")
	}
	link := &dbtype.SessionIdentity{
		ID: id, UserID: userID, Method: identity.Method, Connection: identity.Connection, Subject: identity.Subject,
		Tenant: dbtype.OptionalString(tenant), EmailAtLink: dbtype.OptionalString(identity.Email), CreatedAt: now, LastUsedAt: now,
	}

	query := fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, s.identitiesTable(), identityColumns)
	if _, err := q.Exec(ctx, query, link.ID, link.UserID, string(link.Method), link.Connection, link.Subject, link.Tenant, link.EmailAtLink, now, now); err != nil {
		return nil, errors.Wrap(err, "Exec()")
	}

	return link, nil
}

// UserIn reads the part of userID's user the sign-in decides on, inside tx, sharing its
// row lock so a concurrent change waits. A missing user is NotFound.
func (s *SessionStorageDriver) UserIn(ctx context.Context, tx pgx.Tx, userID ccc.UUID) (*dbtype.User, error) {
	return s.userIn(ctx, tx, userID, "FOR SHARE")
}

// linkDecisionLockClass is the first key of the advisory lock a link decision takes,
// keeping it apart from any advisory lock the application takes on its own.
const linkDecisionLockClass = "session.link-decision"

// LockUserIn reads the user as UserIn does and holds a transaction-scoped advisory lock
// keyed by the user until tx ends, so two link decisions for one user run one after the
// other and the second sees the first's link. An advisory lock rather than a stronger
// row lock: upgrading the row lock deadlocks with a resolver that shared the row before
// the decision, and twice in a row under load, while the advisory lock is independent
// of row locks, so a resolver's own share lock and the key-share lock a session insert
// takes through its foreign key go through.
func (s *SessionStorageDriver) LockUserIn(ctx context.Context, tx pgx.Tx, userID ccc.UUID) (*dbtype.User, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, linkDecisionLockClass, userID.String()); err != nil {
		return nil, errors.Wrap(err, "pgx.Tx.Exec()")
	}

	return s.userIn(ctx, tx, userID, "FOR SHARE")
}

// userIn reads the user with the row lock clause lock.
func (s *SessionStorageDriver) userIn(ctx context.Context, tx pgx.Tx, userID ccc.UUID, lock string) (*dbtype.User, error) {
	query := fmt.Sprintf(`SELECT "Username", "PasswordHash" IS NOT NULL, "Disabled" FROM %s WHERE "Id" = $1 %s`, s.userTable(), lock)

	var u dbtype.User
	if err := tx.QueryRow(ctx, query, userID).Scan(&u.Username, &u.HasPassword, &u.Disabled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("user id %q does not exist", userID)
		}

		return nil, errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}

	return &u, nil
}

// InsertUserIn writes a new user row inside tx and returns its ID.
func (s *SessionStorageDriver) InsertUserIn(ctx context.Context, tx pgx.Tx, user *dbtype.InsertSessionUser) (ccc.UUID, error) {
	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}
	query, args := s.userInsertStatement(id, user)
	if _, err := tx.Exec(ctx, query, args...); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "pgx.Tx.Exec()")
	}

	return id, nil
}

// InsertSessionIn inserts the session row, its auth events and its custom session data
// for a resolved request, inside tx.
func (s *SessionStorageDriver) InsertSessionIn(ctx context.Context, tx pgx.Tx, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) error {
	if req.CustomData != nil && s.customData == nil {
		return errors.New("custom session data provided but no custom session data config is attached")
	}

	row := *insertSession
	row.Username = req.Username
	query, args := s.sessionInsertStatement(id, &row, req)
	if _, err := tx.Exec(ctx, query, args...); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}
	if insertEvent := s.initialAuthEvent(id, req, nil, row.CreatedAt, nil); insertEvent != nil {
		if err := insertEvent(ctx, tx); err != nil {
			return err
		}
	}

	data := req.CustomData
	if data == nil && s.customData != nil && s.customData.Resolver != nil {
		var err error
		data, err = s.customData.Resolver(ctx, tx, req)
		if err != nil {
			return errors.Wrap(err, "CustomSessionDataConfig.Resolver()")
		}
	}
	if data != nil {
		if err := s.insertCustomSessionData(ctx, tx, id, data, false); err != nil {
			return err
		}
	}

	return nil
}

// Identity returns the link for (method, connection, subject), or a NotFound error.
func (s *SessionStorageDriver) Identity(ctx context.Context, method sessioninfo.AuthMethod, connection, subject string) (*dbtype.SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	link, err := s.lookupIdentity(ctx, s.conn, method, connection, subject)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, httpio.NewNotFoundMessagef("identity (%s, %q, %q) is not linked", method, connection, subject)
	}

	return link, nil
}

// IdentitiesByUser lists a user's links, oldest first.
func (s *SessionStorageDriver) IdentitiesByUser(ctx context.Context, userID ccc.UUID) ([]*dbtype.SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return s.identitiesByUser(ctx, s.conn, userID)
}

// IdentitiesByUserIn lists a user's links inside tx, oldest first.
func (s *SessionStorageDriver) IdentitiesByUserIn(ctx context.Context, tx pgx.Tx, userID ccc.UUID) ([]*dbtype.SessionIdentity, error) {
	return s.identitiesByUser(ctx, tx, userID)
}

// identitiesByUser lists a user's links through q, oldest first.
func (s *SessionStorageDriver) identitiesByUser(ctx context.Context, q pgxscan.Querier, userID ccc.UUID) ([]*dbtype.SessionIdentity, error) {
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "UserId" = $1 ORDER BY "CreatedAt", "Id"`, identityColumns, s.identitiesTable())
	var identities []*dbtype.SessionIdentity
	if err := pgxscan.Select(ctx, q, &identities, query, userID); err != nil {
		return nil, errors.Wrap(err, "pgxscan.Select()")
	}

	return identities, nil
}

// LinkIdentity links identity to userID outside the sign-in flow. An identity that is
// already linked is a Conflict.
func (s *SessionStorageDriver) LinkIdentity(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*dbtype.SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	link, err := s.insertLink(ctx, s.conn, userID, identity, tenant, time.Now())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, httpio.NewConflictMessagef("identity (%s, %q, %q) is already linked", identity.Method, identity.Connection, identity.Subject)
		}

		return nil, err
	}

	return link, nil
}

// UnlinkIdentity removes a link, refusing to remove the last means of sign-in of an
// user that has no password.
func (s *SessionStorageDriver) UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	var userID ccc.UUID
	if err := txn.QueryRow(ctx, fmt.Sprintf(`SELECT "UserId" FROM %s WHERE "Id" = $1`, s.identitiesTable()), identityID).Scan(&userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpio.NewNotFoundMessagef("identity %q does not exist", identityID)
		}

		return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}

	// The user row is locked, so concurrent unlinks of its identities run one at a
	// time and can't both leave it without a means of sign-in.
	var hasPassword bool
	lockUser := fmt.Sprintf(`SELECT "PasswordHash" IS NOT NULL FROM %s WHERE "Id" = $1 FOR UPDATE`, s.userTable())
	if err := txn.QueryRow(ctx, lockUser, userID).Scan(&hasPassword); err != nil {
		return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}
	if !hasPassword {
		var links int
		if err := txn.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE "UserId" = $1`, s.identitiesTable()), userID).Scan(&links); err != nil {
			return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
		}
		if links <= 1 {
			return httpio.NewConflictMessageWithError(dbtype.ErrLastSignInMethod, "the user has no other means of sign-in")
		}
	}

	if _, err := txn.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE "Id" = $1`, s.identitiesTable()), identityID); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}

// DestroyUserSessions expires every live session of a user by UserId. That covers
// its own sessions, user-principal impersonations of it, and the sessions it holds as a
// local actor. Their live impersonation records end Revoked.
func (s *SessionStorageDriver) DestroyUserSessions(ctx context.Context, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !s.users {
		return errors.New("DestroyUserSessions needs the auth schema: use Auth storage")
	}

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	now := time.Now()
	if s.impersonation == nil {
		expire := fmt.Sprintf(`UPDATE %s SET "Expired" = TRUE, "UpdatedAt" = $2 WHERE "Expired" = FALSE AND "UserId" = $1`, s.sessionTable())
		if _, err := txn.Exec(ctx, expire, userID, now); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}
	} else {
		// The local-actor records name the actor by username.
		var username string
		err := txn.QueryRow(ctx, fmt.Sprintf(`SELECT "Username" FROM %s WHERE "Id" = $1`, s.userTable()), userID).Scan(&username)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
		}

		// Sessions first: the expiry predicate reads the records while they are still live.
		expire := fmt.Sprintf(`
			UPDATE %s s SET "Expired" = TRUE, "UpdatedAt" = $3
			WHERE s."Expired" = FALSE AND (s."UserId" = $2 OR %s)`, s.sessionTable(), s.heldByLocalActor())
		if _, err := txn.Exec(ctx, expire, username, userID, now); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}

		endRecords := fmt.Sprintf(`
			UPDATE %s i SET "EndedAt" = $3, "EndReason" = $4
			WHERE i."EndedAt" IS NULL AND (
				EXISTS (SELECT 1 FROM %s s WHERE s."Id" = i."SessionId" AND s."UserId" = $2)
				OR (i."ActorUsername" = $1 AND i."ActorRealm" IS NULL))`,
			pgx.Identifier{s.impersonation.TableName}.Sanitize(), s.sessionTable())
		if _, err := txn.Exec(ctx, endRecords, username, userID, now, string(sessioninfo.ImpersonationEndedByRevocation)); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}

// AppendAuthEvent records a step-up or confirmation on a live session, after its
// earlier events, and moves the session's AuthenticatedAt to the event's time. A zero
// event time is now.
func (s *SessionStorageDriver) AppendAuthEvent(ctx context.Context, sessionID ccc.UUID, event *sessioninfo.AuthEvent) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.authEvents == nil {
		return errors.New("auth events are not configured: attach WithAuthEvents")
	}
	if event.Method == "" {
		return httpio.NewBadRequestMessage("an auth event needs a method")
	}
	if event.At.IsZero() {
		event.At = time.Now()
	}

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	// The session row is locked, so concurrent appends take sequence numbers in turn.
	var expired bool
	if err := txn.QueryRow(ctx, fmt.Sprintf(`SELECT "Expired" FROM %s WHERE "Id" = $1 FOR UPDATE`, s.sessionTable()), sessionID).Scan(&expired); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpio.NewNotFoundMessagef("session %q not found", sessionID)
		}

		return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}
	if expired {
		return httpio.NewBadRequestMessage("cannot record an auth event on an expired session")
	}

	var seq int64
	last := fmt.Sprintf(`SELECT COALESCE(MAX("Seq"), 0) FROM %s WHERE "SessionId" = $1`, pgx.Identifier{s.authEvents.TableName}.Sanitize())
	if err := txn.QueryRow(ctx, last, sessionID).Scan(&seq); err != nil {
		return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}
	if err := s.insertAuthEvent(ctx, txn, sessionID, seq+1, event); err != nil {
		return err
	}
	if s.users {
		if _, err := txn.Exec(ctx, fmt.Sprintf(`UPDATE %s SET "AuthenticatedAt" = $2 WHERE "Id" = $1`, s.sessionTable()), sessionID, event.At); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}
