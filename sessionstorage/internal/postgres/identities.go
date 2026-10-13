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

// IdentitiesConfig configures identity links for the PostgreSQL driver. It is populated
// by the public sessionstorage package from a validated unit; the driver performs no
// validation of its own.
type IdentitiesConfig struct {
	// TableName is the name of the identities table.
	TableName string
	// Resolve decides an external identity that is not linked yet, inside the user
	// resolution transaction.
	Resolve func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error)
	// Policy, when set, decides every sign-in once its user is known (see
	// dbtype.PolicyApplies). It runs inside the transaction that inserts the session.
	// Nil allows every sign-in.
	Policy func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*dbtype.SignInDecision, error)
}

// SetIdentities attaches the identities configuration. Sessions of linked identities
// belong to a user, so it also enables the user columns.
func (s *SessionStorageDriver) SetIdentities(config *IdentitiesConfig) {
	s.identities = config
	s.users = true
}

// IdentitiesEnabled reports whether an identities configuration is attached.
func (s *SessionStorageDriver) IdentitiesEnabled() bool {
	return s.identities != nil
}

// identityColumns are the identities table's columns.
const identityColumns = `"Id", "UserId", "Method", "Connection", "Subject", "Tenant", "EmailAtLink", "CreatedAt", "LastUsedAt"`

func (s *SessionStorageDriver) identitiesTable() string {
	return pgx.Identifier{s.identities.TableName}.Sanitize()
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

// readUser reads userID's user inside txn. A missing user is NotFound.
func (s *SessionStorageDriver) readUser(ctx context.Context, txn pgx.Tx, userID ccc.UUID) (*dbtype.User, error) {
	query := fmt.Sprintf(`SELECT "Username", "PasswordHash" IS NOT NULL, "Disabled" FROM %s WHERE "Id" = $1 FOR SHARE`, pgx.Identifier{s.userTableName}.Sanitize())

	var a dbtype.User
	if err := txn.QueryRow(ctx, query, userID).Scan(&a.Username, &a.HasPassword, &a.Disabled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("user id %q does not exist", userID)
		}

		return nil, errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}

	return &a, nil
}

// insertUserSession establishes a session for a request that carries a verified
// identity, in two transactions (see the README's "Storage and schema"):
// resolveIdentity resolves an external identity's user, then decideAndInsert decides
// the sign-in and inserts the session. Each transaction commits unless a hook or the
// driver fails, so a refusal or a pending outcome keeps the hooks' own writes and writes
// no session.
//
// Once the user is known, req.UserID, req.Username and req.User are set to it,
// whatever the outcome.
func (s *SessionStorageDriver) insertUserSession(ctx context.Context, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) error {
	if s.identities == nil {
		return dbtype.ErrIdentitiesNotConfigured
	}
	if req.CustomData != nil && s.customData == nil {
		return errors.New("custom session data provided but no custom session data config is attached")
	}

	resolved := *req
	resolved.User = nil
	defer func() { req.UserID, req.Username, req.User = resolved.UserID, resolved.Username, resolved.User }()

	source, tenant := sessioninfo.UserNamed, ""
	switch {
	case dbtype.IsExternal(req.Identity):
		var (
			stop error
			err  error
		)
		source, tenant, stop, err = s.resolveIdentity(ctx, &resolved)
		if err != nil {
			return err
		}
		if stop != nil {
			return stop
		}
		// The resolution has committed, so a link or a provisioned user is reported
		// even when the decision then fails.
		resolved.User = &sessioninfo.SignInUser{ID: resolved.UserID, Username: resolved.Username, Source: source, Tenant: tenant}
	case req.UserID.IsNil():
		return errors.New("a password sign-in names its user in req.UserID")
	}

	return s.decideAndInsert(ctx, id, insertSession, &resolved, source, tenant)
}

// resolveIdentity is the first transaction of insertUserSession. It sets req.UserID
// (and req.Username for a provisioned user) and reports how the user was found
// and the link's tenant. stop is a refusal or a pending confirmation; it still commits.
// When two first sign-ins of one identity race, the loser's link insert fails on the
// identities key, and its resolution runs once more and finds the winner's link.
func (s *SessionStorageDriver) resolveIdentity(
	ctx context.Context, req *sessioninfo.NewSessionRequest,
) (source sessioninfo.UserSource, tenant string, stop, err error) {
	base := *req
	for attempt := 1; ; attempt++ {
		// Each attempt starts from the caller's request.
		*req = base
		source, tenant, stop, err = s.tryResolveIdentity(ctx, req)
		if err == nil {
			return source, tenant, stop, nil
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			switch {
			case pgErr.ConstraintName == usernameIndex:
				return "", "", nil, httpio.NewConflictMessagef("username %q already exists", req.Username)
			case pgErr.TableName == s.identities.TableName && attempt == 1:
				continue
			}
		}

		return "", "", nil, err
	}
}

// tryResolveIdentity is one attempt of resolveIdentity. A linked identity resolves to
// its user and its LastUsedAt is touched. An unlinked one goes to the user
// resolver (applyResolution).
func (s *SessionStorageDriver) tryResolveIdentity(
	ctx context.Context, req *sessioninfo.NewSessionRequest,
) (source sessioninfo.UserSource, tenant string, stop, err error) {
	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return "", "", nil, errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	now := time.Now()
	link, err := s.lookupIdentity(ctx, txn, req.Identity.Method, req.Identity.Connection, req.Identity.Subject)
	if err != nil {
		return "", "", nil, err
	}
	if link != nil {
		req.UserID = link.UserID
		touch := fmt.Sprintf(`UPDATE %s SET "LastUsedAt" = $2 WHERE "Id" = $1`, s.identitiesTable())
		if _, err := txn.Exec(ctx, touch, link.ID, now); err != nil {
			return "", "", nil, errors.Wrap(err, "pgx.Tx.Exec()")
		}
		source = sessioninfo.UserExistingLink
		if link.Tenant != nil {
			tenant = *link.Tenant
		}
	} else {
		res, err := s.identities.Resolve(ctx, txn, req)
		if err != nil {
			return "", "", nil, errors.Wrap(err, "IdentitiesConfig.Resolve()")
		}
		if source, tenant, stop, err = s.applyResolution(ctx, txn, req, res, now); err != nil {
			return "", "", nil, err
		}
	}

	if err := txn.Commit(ctx); err != nil {
		return "", "", nil, errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return source, tenant, stop, nil
}

// decideAndInsert is the second transaction of insertUserSession. It reads req's
// user, sets req.User and decides the sign-in (dbtype.DecideSignIn). When the
// sign-in goes ahead it inserts the session. A refusal or an MFA wait is returned after
// the policy's own writes commit.
func (s *SessionStorageDriver) decideAndInsert(
	ctx context.Context, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest, source sessioninfo.UserSource, tenant string,
) error {
	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	acct, err := s.readUser(ctx, txn, req.UserID)
	if err != nil {
		return err
	}
	req.User = dbtype.SignInUser(req, acct, source, tenant)

	var policy func(ctx context.Context) (*dbtype.SignInDecision, error)
	if s.identities.Policy != nil {
		policy = func(ctx context.Context) (*dbtype.SignInDecision, error) { return s.identities.Policy(ctx, txn, req) }
	}
	stop, err := dbtype.DecideSignIn(ctx, req, acct, policy)
	if err != nil {
		return errors.Wrap(err, "dbtype.DecideSignIn()")
	}
	if stop == nil {
		if err := s.insertResolvedSession(ctx, txn, id, insertSession, req); err != nil {
			return err
		}
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return stop //nolint:wrapcheck // the refusal or the wait as the decision made it
}

// insertResolvedSession inserts the session row, its first auth event and its custom
// session data for a resolved request.
func (s *SessionStorageDriver) insertResolvedSession(ctx context.Context, txn pgx.Tx, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) error {
	row := *insertSession
	row.Username = req.Username
	query, args := s.sessionInsertStatement(id, &row, req)
	if _, err := txn.Exec(ctx, query, args...); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}
	if insertEvent := s.initialAuthEvent(id, req, nil, row.CreatedAt, nil); insertEvent != nil {
		if err := insertEvent(ctx, txn); err != nil {
			return err
		}
	}

	data := req.CustomData
	if data == nil && s.customData != nil && s.customData.Resolver != nil {
		var err error
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

	return nil
}

// applyResolution acts on the user resolver's answer for an unlinked identity. A link
// or a new user sets req.UserID (and req.Username for a new user) and reports how
// the user was found and its tenant. A pending confirmation or a refusal is returned
// as stop.
func (s *SessionStorageDriver) applyResolution(
	ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest, res *dbtype.Resolution, now time.Time,
) (source sessioninfo.UserSource, tenant string, stop, err error) {
	if res == nil {
		res = &dbtype.Resolution{}
	}

	switch res.Outcome {
	case dbtype.RejectIdentity:
		return "", "", dbtype.Refusal(res.Refusal, sessioninfo.RefusedIdentityRejected, dbtype.ErrIdentityRejected, "identity rejected"), nil
	case dbtype.LinkIdentity:
		acct, err := s.readUser(ctx, txn, res.UserID)
		if err != nil {
			return "", "", nil, err
		}
		if acct.HasPassword && !res.TrustedForLinking {
			return "", "", dbtype.Refusal("", sessioninfo.RefusedIdentityRejected, dbtype.ErrLinkRequiresConfirmation, "identity requires confirmation"), nil
		}
		if _, err := s.insertLink(ctx, txn, res.UserID, req.Identity, res.Tenant, now); err != nil {
			return "", "", nil, err
		}
		req.UserID = res.UserID

		return sessioninfo.UserNewLink, res.Tenant, nil, nil
	case dbtype.ProvisionUser:
		if res.NewUser == nil {
			return "", "", nil, errors.New("the user resolver provisioned no user: Resolution.NewUser is nil")
		}
		id, err := ccc.NewUUID()
		if err != nil {
			return "", "", nil, errors.Wrap(err, "ccc.NewUUID()")
		}
		req.Username = res.NewUser.Username
		query, args := s.userInsertStatement(id, res.NewUser)
		if _, err := txn.Exec(ctx, query, args...); err != nil {
			return "", "", nil, errors.Wrap(err, "pgx.Tx.Exec()")
		}
		if _, err := s.insertLink(ctx, txn, id, req.Identity, res.Tenant, now); err != nil {
			return "", "", nil, err
		}
		req.UserID = id
		if res.OnProvisioned != nil {
			if err := res.OnProvisioned(ctx, id); err != nil {
				return "", "", nil, errors.Wrap(err, "Resolution.OnProvisioned()")
			}
		}

		return sessioninfo.UserProvisioned, res.Tenant, nil, nil
	case dbtype.RequireConfirmation:
		acct, err := s.readUser(ctx, txn, res.UserID)
		if err != nil {
			return "", "", nil, err
		}

		return "", "", &dbtype.PendingSignInError{
			Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(res.UserID), Username: acct.Username, Tenant: res.Tenant,
		}, nil
	default:
		return "", "", nil, errors.Newf("unknown user resolver outcome %d", res.Outcome)
	}
}

// Identity returns the link for (method, connection, subject), or a NotFound error.
func (s *SessionStorageDriver) Identity(ctx context.Context, method sessioninfo.AuthMethod, connection, subject string) (*dbtype.SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.identities == nil {
		return nil, dbtype.ErrIdentitiesNotConfigured
	}

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

	if s.identities == nil {
		return nil, dbtype.ErrIdentitiesNotConfigured
	}

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "UserId" = $1 ORDER BY "CreatedAt", "Id"`, identityColumns, s.identitiesTable())
	var identities []*dbtype.SessionIdentity
	if err := pgxscan.Select(ctx, s.conn, &identities, query, userID); err != nil {
		return nil, errors.Wrap(err, "pgxscan.Select()")
	}

	return identities, nil
}

// LinkIdentity links identity to userID outside the sign-in flow. An identity that is
// already linked is a Conflict.
func (s *SessionStorageDriver) LinkIdentity(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*dbtype.SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.identities == nil {
		return nil, dbtype.ErrIdentitiesNotConfigured
	}

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

	if s.identities == nil {
		return dbtype.ErrIdentitiesNotConfigured
	}

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
	lockUser := fmt.Sprintf(`SELECT "PasswordHash" IS NOT NULL FROM %s WHERE "Id" = $1 FOR UPDATE`, pgx.Identifier{s.userTableName}.Sanitize())
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
		expire := fmt.Sprintf(`UPDATE %s SET "Expired" = TRUE, "UpdatedAt" = $2 WHERE "Expired" = FALSE AND "UserId" = $1`, pgx.Identifier{s.sessionTableName}.Sanitize())
		if _, err := txn.Exec(ctx, expire, userID, now); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}
	} else {
		// The local-actor records name the actor by username.
		var username string
		err := txn.QueryRow(ctx, fmt.Sprintf(`SELECT "Username" FROM %s WHERE "Id" = $1`, pgx.Identifier{s.userTableName}.Sanitize()), userID).Scan(&username)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
		}

		// Sessions first: the expiry predicate reads the records while they are still live.
		expire := fmt.Sprintf(`
			UPDATE "%s" s SET "Expired" = TRUE, "UpdatedAt" = $3
			WHERE s."Expired" = FALSE AND (s."UserId" = $2 OR %s)`, s.sessionTableName, s.heldByLocalActor())
		if _, err := txn.Exec(ctx, expire, username, userID, now); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}

		endRecords := fmt.Sprintf(`
			UPDATE %s i SET "EndedAt" = $3, "EndReason" = $4
			WHERE i."EndedAt" IS NULL AND (
				EXISTS (SELECT 1 FROM "%s" s WHERE s."Id" = i."SessionId" AND s."UserId" = $2)
				OR (i."ActorUsername" = $1 AND i."ActorRealm" IS NULL))`,
			pgx.Identifier{s.impersonation.TableName}.Sanitize(), s.sessionTableName)
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
	if err := txn.QueryRow(ctx, fmt.Sprintf(`SELECT "Expired" FROM %s WHERE "Id" = $1 FOR UPDATE`, pgx.Identifier{s.sessionTableName}.Sanitize()), sessionID).Scan(&expired); err != nil {
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
		if _, err := txn.Exec(ctx, fmt.Sprintf(`UPDATE %s SET "AuthenticatedAt" = $2 WHERE "Id" = $1`, pgx.Identifier{s.sessionTableName}.Sanitize()), sessionID, event.At); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}
