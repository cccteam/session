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
	// Resolve decides an external identity that is not linked yet, inside the session
	// transaction.
	Resolve func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error)
	// Policy, when set, decides every sign-in once its account is known (see
	// dbtype.PolicyApplies). Nil allows.
	Policy func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*dbtype.SignInDecision, error)
}

// SetIdentities attaches the identities configuration. Identity links key sessions by
// account, so it enables the accounts columns as well.
func (s *SessionStorageDriver) SetIdentities(config *IdentitiesConfig) {
	s.identities = config
	s.accounts = true
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

// readAccount reads userID's account inside txn; a missing account is NotFound.
func (s *SessionStorageDriver) readAccount(ctx context.Context, txn pgx.Tx, userID ccc.UUID) (*dbtype.Account, error) {
	query := fmt.Sprintf(`SELECT "Username", "PasswordHash" IS NOT NULL, "Disabled" FROM %s WHERE "Id" = $1 FOR SHARE`, pgx.Identifier{s.userTableName}.Sanitize())

	var a dbtype.Account
	if err := txn.QueryRow(ctx, query, userID).Scan(&a.Username, &a.HasPassword, &a.Disabled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("user id %q does not exist", userID)
		}

		return nil, errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}

	return &a, nil
}

// insertAccountSession establishes a session for a request that carries a verified
// identity, in one transaction: it resolves the account (resolveAccount), then inserts
// the session row with the account's UserId and username, its first auth event, and
// its custom session data. A refusal or a pending outcome writes nothing. When two first
// sign-ins of one identity race, the loser's link insert fails on the identities key and
// the sign-in runs once more, finding the winner's link.
func (s *SessionStorageDriver) insertAccountSession(ctx context.Context, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) error {
	if s.identities == nil {
		return dbtype.ErrIdentitiesNotConfigured
	}
	if req.CustomData != nil && s.customData == nil {
		return errors.New("custom session data provided but no custom session data config is attached")
	}

	for attempt := 1; ; attempt++ {
		// Each attempt starts from the caller's request.
		resolved := *req
		err := s.tryAccountSession(ctx, id, insertSession, &resolved)
		if err == nil {
			req.UserID, req.Username = resolved.UserID, resolved.Username

			return nil
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			switch {
			case pgErr.ConstraintName == usernameIndex:
				return httpio.NewConflictMessagef("username %q already exists", resolved.Username)
			case pgErr.TableName == s.identities.TableName && attempt == 1:
				continue
			}
		}

		return err
	}
}

// tryAccountSession is one attempt of insertAccountSession.
func (s *SessionStorageDriver) tryAccountSession(ctx context.Context, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) error {
	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	pending, err := s.resolveAccount(ctx, txn, req)
	if err != nil {
		return err
	}
	if pending != nil {
		return pending
	}

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
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}

// resolveAccount resolves the account a sign-in establishes a session for, inside txn,
// and sets req.UserID and req.Username to it. An external identity is looked up by
// (Method, Connection, Subject): a linked identity is that account's (its LastUsedAt is
// touched); an unknown one goes to the account resolver, whose Resolution is acted on.
// A password identity names its account in req.UserID. The account must be enabled.
// The sign-in policy then decides, when it applies. A pending outcome is returned as
// the first result; a refusal as an error.
func (s *SessionStorageDriver) resolveAccount(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*dbtype.PendingSignInError, error) {
	var (
		acct        *dbtype.Account
		provisioned bool
		tenant      string
	)
	now := time.Now()

	switch {
	case dbtype.IsExternal(req.Identity):
		link, err := s.lookupIdentity(ctx, txn, req.Identity.Method, req.Identity.Connection, req.Identity.Subject)
		if err != nil {
			return nil, err
		}
		if link != nil {
			req.UserID = link.UserID
			touch := fmt.Sprintf(`UPDATE %s SET "LastUsedAt" = $2 WHERE "Id" = $1`, s.identitiesTable())
			if _, err := txn.Exec(ctx, touch, link.ID, now); err != nil {
				return nil, errors.Wrap(err, "pgx.Tx.Exec()")
			}

			break
		}

		res, err := s.identities.Resolve(ctx, txn, req)
		if err != nil {
			return nil, errors.Wrap(err, "IdentitiesConfig.Resolve()")
		}
		pending, newAccount, err := s.applyResolution(ctx, txn, req, res, now)
		if err != nil || pending != nil {
			return pending, err
		}
		acct, provisioned, tenant = newAccount, newAccount != nil, res.Tenant
	case req.UserID.IsNil():
		return nil, errors.New("a password sign-in names its account in req.UserID")
	}

	if acct == nil {
		var err error
		if acct, err = s.readAccount(ctx, txn, req.UserID); err != nil {
			return nil, err
		}
	}

	var policy func(ctx context.Context) (*dbtype.SignInDecision, error)
	if s.identities.Policy != nil {
		policy = func(ctx context.Context) (*dbtype.SignInDecision, error) { return s.identities.Policy(ctx, txn, req) }
	}

	pending, err := dbtype.DecideSignIn(ctx, req, acct, provisioned, tenant, policy)
	if err != nil {
		return nil, errors.Wrap(err, "dbtype.DecideSignIn()")
	}

	return pending, nil
}

// applyResolution acts on the account resolver's answer for an unlinked identity: it
// links or provisions (setting req.UserID), or returns the pending confirmation or the
// refusal. For a provisioned account it returns the new account.
func (s *SessionStorageDriver) applyResolution(
	ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest, res *dbtype.Resolution, now time.Time,
) (*dbtype.PendingSignInError, *dbtype.Account, error) {
	if res == nil {
		res = &dbtype.Resolution{}
	}

	switch res.Outcome {
	case dbtype.RejectIdentity:
		return nil, nil, errors.Wrap(dbtype.Refusal(res.Refusal, sessioninfo.RefusedIdentityRejected, dbtype.ErrIdentityRejected, "identity rejected"), "RejectIdentity")
	case dbtype.LinkIdentity:
		acct, err := s.readAccount(ctx, txn, res.UserID)
		if err != nil {
			return nil, nil, err
		}
		if acct.HasPassword && !res.TrustedForLinking {
			return nil, nil, errors.Wrap(dbtype.Refusal("", sessioninfo.RefusedIdentityRejected, dbtype.ErrLinkRequiresConfirmation, "identity requires confirmation"), "LinkIdentity")
		}
		if _, err := s.insertLink(ctx, txn, res.UserID, req.Identity, res.Tenant, now); err != nil {
			return nil, nil, err
		}
		req.UserID = res.UserID

		return nil, acct, nil
	case dbtype.ProvisionAccount:
		if res.NewUser == nil {
			return nil, nil, errors.New("the account resolver provisioned no account: Resolution.NewUser is nil")
		}
		id, err := ccc.NewUUID()
		if err != nil {
			return nil, nil, errors.Wrap(err, "ccc.NewUUID()")
		}
		req.Username = res.NewUser.Username
		query, args := s.userInsertStatement(id, res.NewUser)
		if _, err := txn.Exec(ctx, query, args...); err != nil {
			return nil, nil, errors.Wrap(err, "pgx.Tx.Exec()")
		}
		if _, err := s.insertLink(ctx, txn, id, req.Identity, res.Tenant, now); err != nil {
			return nil, nil, err
		}
		req.UserID = id
		if res.OnProvisioned != nil {
			if err := res.OnProvisioned(ctx, id); err != nil {
				return nil, nil, errors.Wrap(err, "Resolution.OnProvisioned()")
			}
		}

		return nil, &dbtype.Account{Username: res.NewUser.Username, HasPassword: res.NewUser.PasswordHash != nil, Disabled: res.NewUser.Disabled}, nil
	case dbtype.RequireConfirmation:
		acct, err := s.readAccount(ctx, txn, res.UserID)
		if err != nil {
			return nil, nil, err
		}

		return &dbtype.PendingSignInError{
			Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(res.UserID), Username: acct.Username, Tenant: res.Tenant,
		}, nil, nil
	default:
		return nil, nil, errors.Newf("unknown account resolver outcome %d", res.Outcome)
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

// IdentitiesByUser lists an account's links, oldest first.
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
// account that has no password.
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

	// The account row is locked, so concurrent unlinks of its identities run one at a
	// time and can't both leave it without a means of sign-in.
	var hasPassword bool
	lockAccount := fmt.Sprintf(`SELECT "PasswordHash" IS NOT NULL FROM %s WHERE "Id" = $1 FOR UPDATE`, pgx.Identifier{s.userTableName}.Sanitize())
	if err := txn.QueryRow(ctx, lockAccount, userID).Scan(&hasPassword); err != nil {
		return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}
	if !hasPassword {
		var links int
		if err := txn.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE "UserId" = $1`, s.identitiesTable()), userID).Scan(&links); err != nil {
			return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
		}
		if links <= 1 {
			return httpio.NewConflictMessageWithError(dbtype.ErrLastSignInMethod, "the account has no other means of sign-in")
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

// DestroyUserSessions expires every live session of an account, by UserId: its own
// sessions and the user-principal impersonations of it, together with the live
// impersonation records of those sessions and of the sessions it holds as a local actor,
// which end Revoked.
func (s *SessionStorageDriver) DestroyUserSessions(ctx context.Context, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !s.accounts {
		return errors.New("DestroyUserSessions needs the accounts schema: use account storage")
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
	if s.accounts {
		if _, err := txn.Exec(ctx, fmt.Sprintf(`UPDATE %s SET "AuthenticatedAt" = $2 WHERE "Id" = $1`, pgx.Identifier{s.sessionTableName}.Sanitize()), sessionID, event.At); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}
