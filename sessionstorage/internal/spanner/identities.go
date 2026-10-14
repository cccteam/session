package spanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"google.golang.org/grpc/codes"
)

// Column names the driver writes in more than one place.
const (
	idColumn       = "Id"
	usernameColumn = "Username"
)

// The sign-in flow (internal/signinflow) drives the primitives below inside the
// read-write transactions Transact opens; the mutations of a sign-in live here, their
// sequence there. Spanner hides buffered writes from reads in the same transaction.

// identityColumns are the identities table's columns, in identityRow's order.
const identityColumns = "Id, UserId, Method, Connection, Subject, Tenant, EmailAtLink, CreatedAt, LastUsedAt"

// identityRow is an identities table row as Spanner returns it.
type identityRow struct {
	ID          string             `spanner:"Id"`
	UserID      string             `spanner:"UserId"`
	Method      string             `spanner:"Method"`
	Connection  string             `spanner:"Connection"`
	Subject     string             `spanner:"Subject"`
	Tenant      spanner.NullString `spanner:"Tenant"`
	EmailAtLink spanner.NullString `spanner:"EmailAtLink"`
	CreatedAt   time.Time          `spanner:"CreatedAt"`
	LastUsedAt  time.Time          `spanner:"LastUsedAt"`
}

func (r *identityRow) identity() (*dbtype.SessionIdentity, error) {
	id, err := ccc.UUIDFromString(r.ID)
	if err != nil {
		return nil, errors.Wrap(err, "ccc.UUIDFromString()")
	}
	userID, err := ccc.UUIDFromString(r.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "ccc.UUIDFromString()")
	}

	return &dbtype.SessionIdentity{
		ID: id, UserID: userID, Method: sessioninfo.AuthMethod(r.Method), Connection: r.Connection, Subject: r.Subject,
		Tenant: nullStringPtr(r.Tenant), EmailAtLink: nullStringPtr(r.EmailAtLink), CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt,
	}, nil
}

// querier is a single-use read, a read-only transaction or a read-write transaction.
type querier interface {
	Query(ctx context.Context, statement spanner.Statement) *spanner.RowIterator
}

// queryIdentities runs stmt over the identities table and returns its rows.
func queryIdentities(ctx context.Context, q querier, stmt spanner.Statement) ([]*dbtype.SessionIdentity, error) {
	var identities []*dbtype.SessionIdentity
	err := q.Query(ctx, stmt).Do(func(row *spanner.Row) error {
		var r identityRow
		if err := row.ToStruct(&r); err != nil {
			return errors.Wrap(err, "spanner.Row.ToStruct()")
		}
		identity, err := r.identity()
		if err != nil {
			return err
		}
		identities = append(identities, identity)

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.RowIterator.Do()")
	}

	return identities, nil
}

// Transact runs fn in a read-write transaction, which Spanner may retry, and commits
// when fn returns nil.
func (s *SessionStorageDriver) Transact(ctx context.Context, fn func(ctx context.Context, tx *spanner.ReadWriteTransaction) error) error {
	if _, err := s.spanner.ReadWriteTransaction(ctx, fn); err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// SignInConflict classifies an AlreadyExists a sign-in's transaction ended with: the
// user table's username index, or else the identities table's key.
func (s *SessionStorageDriver) SignInConflict(err error) dbtype.SignInConflict {
	if spanner.ErrCode(err) != codes.AlreadyExists {
		return dbtype.NoSignInConflict
	}
	if strings.Contains(err.Error(), s.usernameIndex()) {
		return dbtype.UsernameConflict
	}

	return dbtype.IdentityConflict
}

// IdentityIn returns the link for (method, connection, subject) inside tx, or nil.
func (s *SessionStorageDriver) IdentityIn(
	ctx context.Context, tx *spanner.ReadWriteTransaction, method sessioninfo.AuthMethod, connection, subject string,
) (*dbtype.SessionIdentity, error) {
	return s.lookupIdentity(ctx, tx, method, connection, subject)
}

// lookupIdentity returns the link for (method, connection, subject), or nil.
func (s *SessionStorageDriver) lookupIdentity(ctx context.Context, q querier, method sessioninfo.AuthMethod, connection, subject string) (*dbtype.SessionIdentity, error) {
	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE Method = @method AND Connection = @connection AND Subject = @subject`,
		identityColumns, s.identitiesTableName))
	stmt.Params["method"] = string(method)
	stmt.Params["connection"] = connection
	stmt.Params["subject"] = subject

	identities, err := queryIdentities(ctx, q, stmt)
	if err != nil || len(identities) == 0 {
		return nil, err
	}

	return identities[0], nil
}

// TouchIdentityIn buffers the move of the link's LastUsedAt to the commit time.
func (s *SessionStorageDriver) TouchIdentityIn(_ context.Context, tx *spanner.ReadWriteTransaction, linkID ccc.UUID) error {
	touch := spanner.UpdateMap(s.identitiesTableName, map[string]any{idColumn: linkID, "LastUsedAt": spanner.CommitTimestamp})
	if err := tx.BufferWrite([]*spanner.Mutation{touch}); err != nil {
		return errors.Wrap(err, "txn.BufferWrite()")
	}

	return nil
}

// LinkIdentityIn buffers a new link of identity to userID.
func (s *SessionStorageDriver) LinkIdentityIn(
	_ context.Context, tx *spanner.ReadWriteTransaction, userID ccc.UUID, identity *sessioninfo.Identity, tenant string,
) error {
	_, mutation, err := s.newIdentityLink(userID, identity, tenant)
	if err != nil {
		return err
	}
	if err := tx.BufferWrite([]*spanner.Mutation{mutation}); err != nil {
		return errors.Wrap(err, "txn.BufferWrite()")
	}

	return nil
}

// newIdentityLink renders a new link of identity to userID and its insert mutation. The
// mutation writes CreatedAt and LastUsedAt with the commit timestamp; the link carries
// them zero until the commit reports it.
func (s *SessionStorageDriver) newIdentityLink(userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*dbtype.SessionIdentity, *spanner.Mutation, error) {
	if !dbtype.IsExternal(identity) || identity.Subject == "" {
		return nil, nil, httpio.NewBadRequestMessage("only an external identity with a subject can be linked")
	}

	id, err := ccc.NewUUID()
	if err != nil {
		return nil, nil, errors.Wrap(err, "ccc.NewUUID()")
	}
	link := &dbtype.SessionIdentity{
		ID: id, UserID: userID, Method: identity.Method, Connection: identity.Connection, Subject: identity.Subject,
		Tenant: dbtype.OptionalString(tenant), EmailAtLink: dbtype.OptionalString(identity.Email),
	}

	return link, spanner.InsertMap(s.identitiesTableName, map[string]any{
		idColumn: link.ID, "UserId": link.UserID, "Method": string(link.Method), "Connection": link.Connection, "Subject": link.Subject,
		"Tenant": nullString(link.Tenant), "EmailAtLink": nullString(link.EmailAtLink), "CreatedAt": spanner.CommitTimestamp, "LastUsedAt": spanner.CommitTimestamp,
	}), nil
}

// UserIn reads the part of userID's user the sign-in decides on, inside tx. A missing
// user is NotFound.
func (s *SessionStorageDriver) UserIn(ctx context.Context, tx *spanner.ReadWriteTransaction, userID ccc.UUID) (*dbtype.User, error) {
	row, err := tx.ReadRow(ctx, s.userTableName, spanner.Key{userID.String()}, []string{usernameColumn, "PasswordHash", "Disabled"})
	if err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return nil, httpio.NewNotFoundMessagef("user id %q does not exist", userID)
		}

		return nil, errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
	}

	var (
		u    dbtype.User
		hash spanner.NullString
	)
	if err := row.Columns(&u.Username, &hash, &u.Disabled); err != nil {
		return nil, errors.Wrap(err, "spanner.Row.Columns()")
	}
	u.HasPassword = hash.Valid

	return &u, nil
}

// LockUserIn reads the user as UserIn does. The read-write transaction is serializable:
// when two link decisions for one user race, Spanner aborts one, the client reruns it,
// and the rerun sees the other's link.
func (s *SessionStorageDriver) LockUserIn(ctx context.Context, tx *spanner.ReadWriteTransaction, userID ccc.UUID) (*dbtype.User, error) {
	return s.UserIn(ctx, tx, userID)
}

// InsertUserIn buffers a new user row and returns its ID.
func (s *SessionStorageDriver) InsertUserIn(_ context.Context, tx *spanner.ReadWriteTransaction, insertUser *dbtype.InsertSessionUser) (ccc.UUID, error) {
	user, mutation, err := newUserMutation(s.userTableName, insertUser)
	if err != nil {
		return ccc.NilUUID, err
	}
	if err := tx.BufferWrite([]*spanner.Mutation{mutation}); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "txn.BufferWrite()")
	}

	return user.ID, nil
}

// InsertSessionIn buffers the session row, its auth events and its custom session data
// for a resolved request.
func (s *SessionStorageDriver) InsertSessionIn(
	ctx context.Context, tx *spanner.ReadWriteTransaction, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest,
) error {
	if req.CustomData != nil && s.customData == nil {
		return errors.New("custom session data provided but no custom session data config is attached")
	}

	row := *insertSession
	row.Username = req.Username
	sessionMutation, err := s.sessionInsertMutation(id, &row, req)
	if err != nil {
		return err
	}
	mutations := append([]*spanner.Mutation{sessionMutation}, s.initialAuthEventMutations(id, req, nil)...)
	if err := tx.BufferWrite(mutations); err != nil {
		return errors.Wrap(err, "txn.BufferWrite()")
	}

	data := req.CustomData
	if data == nil && s.customData != nil && s.customData.Resolver != nil {
		data, err = s.customData.Resolver(ctx, tx, req)
		if err != nil {
			return errors.Wrap(err, "CustomSessionDataConfig.Resolver()")
		}
	}
	if data != nil {
		m, err := s.customDataMutation(id, data, spanner.InsertMap)
		if err != nil {
			return err
		}
		if err := tx.BufferWrite([]*spanner.Mutation{m}); err != nil {
			return errors.Wrap(err, "txn.BufferWrite()")
		}
	}

	return nil
}

// newUserMutation renders a new user row and its insert mutation.
func newUserMutation(table string, insertUser *dbtype.InsertSessionUser) (*dbtype.SessionUser, *spanner.Mutation, error) {
	id, err := ccc.NewUUID()
	if err != nil {
		return nil, nil, errors.Wrap(err, "ccc.NewUUID()")
	}
	user := &dbtype.SessionUser{ID: id, Username: insertUser.Username, PasswordHash: insertUser.PasswordHash, Disabled: insertUser.Disabled}

	passwordHash, err := passwordHashValue(user.PasswordHash)
	if err != nil {
		return nil, nil, err
	}
	mutation, err := spanner.InsertStruct(table, &struct {
		ID           ccc.UUID           `spanner:"Id"`
		Username     string             `spanner:"Username"`
		PasswordHash spanner.NullString `spanner:"PasswordHash"`
		Disabled     bool               `spanner:"Disabled"`
	}{ID: user.ID, Username: user.Username, PasswordHash: passwordHash, Disabled: user.Disabled})
	if err != nil {
		return nil, nil, errors.Wrap(err, "spanner.InsertStruct()")
	}

	return user, mutation, nil
}

// Identity returns the link for (method, connection, subject), or a NotFound error.
func (s *SessionStorageDriver) Identity(ctx context.Context, method sessioninfo.AuthMethod, connection, subject string) (*dbtype.SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	link, err := s.lookupIdentity(ctx, s.spanner.Single(), method, connection, subject)
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

	return queryIdentities(ctx, s.spanner.Single(), s.identitiesByUserStatement(userID))
}

// IdentitiesByUserIn lists a user's links inside tx, oldest first.
func (s *SessionStorageDriver) IdentitiesByUserIn(ctx context.Context, tx *spanner.ReadWriteTransaction, userID ccc.UUID) ([]*dbtype.SessionIdentity, error) {
	return queryIdentities(ctx, tx, s.identitiesByUserStatement(userID))
}

// identitiesByUserStatement selects a user's links, oldest first.
func (s *SessionStorageDriver) identitiesByUserStatement(userID ccc.UUID) spanner.Statement {
	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE UserId = @userId ORDER BY CreatedAt, Id`, identityColumns, s.identitiesTableName))
	stmt.Params["userId"] = userID.String()

	return stmt
}

// LinkIdentity links identity to userID outside the sign-in flow. An identity that is
// already linked is a Conflict.
func (s *SessionStorageDriver) LinkIdentity(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*dbtype.SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	link, mutation, err := s.newIdentityLink(userID, identity, tenant)
	if err != nil {
		return nil, err
	}
	committedAt, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation})
	if err != nil {
		if spanner.ErrCode(err) == codes.AlreadyExists {
			return nil, httpio.NewConflictMessagef("identity (%s, %q, %q) is already linked", identity.Method, identity.Connection, identity.Subject)
		}

		return nil, errors.Wrap(err, "spanner.Client.Apply()")
	}
	// The link's times are the commit's, which Apply reports.
	link.CreatedAt, link.LastUsedAt = committedAt, committedAt

	return link, nil
}

// UnlinkIdentity removes a link, refusing to remove the last means of sign-in of an
// user that has no password.
func (s *SessionStorageDriver) UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		row, err := txn.ReadRow(ctx, s.identitiesTableName, spanner.Key{identityID.String()}, []string{"UserId"})
		if err != nil {
			if spanner.ErrCode(err) == codes.NotFound {
				return httpio.NewNotFoundMessagef("identity %q does not exist", identityID)
			}

			return errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
		}
		var userID string
		if err := row.Column(0, &userID); err != nil {
			return errors.Wrap(err, "spanner.Row.Column()")
		}
		uid, err := ccc.UUIDFromString(userID)
		if err != nil {
			return errors.Wrap(err, "ccc.UUIDFromString()")
		}

		user, err := s.UserIn(ctx, txn, uid)
		if err != nil {
			return err
		}
		if !user.HasPassword {
			count := spanner.NewStatement(fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE UserId = @userId`, s.identitiesTableName))
			count.Params["userId"] = userID
			var links int64
			if err := txn.Query(ctx, count).Do(func(r *spanner.Row) error { return r.Column(0, &links) }); err != nil {
				return errors.Wrap(err, "spanner.RowIterator.Do()")
			}
			if links <= 1 {
				return httpio.NewConflictMessageWithError(dbtype.ErrLastSignInMethod, "the user has no other means of sign-in")
			}
		}

		if err := txn.BufferWrite([]*spanner.Mutation{spanner.Delete(s.identitiesTableName, spanner.Key{identityID.String()})}); err != nil {
			return errors.Wrap(err, "txn.BufferWrite()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
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

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		// The local-actor records name the actor by username.
		var username string
		row, err := txn.ReadRow(ctx, s.userTableName, spanner.Key{userID.String()}, []string{usernameColumn})
		switch {
		case err == nil:
			if err := row.Column(0, &username); err != nil {
				return errors.Wrap(err, "spanner.Row.Column()")
			}
		case spanner.ErrCode(err) != codes.NotFound:
			return errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
		}

		// The sessions are selected first and expired by id: the selection reads the
		// records while they are still live, and once a statement has written the commit
		// timestamp to a table, nothing later in the transaction may read that table.
		selectSessions := spanner.NewStatement(fmt.Sprintf(`
			SELECT s.Id, s.Expired
			FROM %s s
			WHERE s.UserId = @userId OR %s`, s.sessionTableName, s.heldByLocalActor()))
		selectSessions.Params["userId"] = userID.String()
		if s.impersonation != nil {
			selectSessions.Params["username"] = username
		}
		ids, live, err := selectSessionIDs(ctx, txn, selectSessions)
		if err != nil {
			return err
		}
		if err := s.expireSessions(ctx, txn, live); err != nil {
			return err
		}

		if s.impersonation != nil {
			endRecords := spanner.NewStatement(fmt.Sprintf(`
				UPDATE %s
				SET EndedAt = PENDING_COMMIT_TIMESTAMP(), EndReason = @reason
				WHERE EndedAt IS NULL AND (SessionId IN UNNEST(@ids) OR (ActorUsername = @username AND ActorRealm IS NULL))`, s.impersonation.TableName))
			endRecords.Params["ids"] = ids
			endRecords.Params["username"] = username
			endRecords.Params["reason"] = string(sessioninfo.ImpersonationEndedByRevocation)
			if _, err := txn.Update(ctx, endRecords); err != nil {
				return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
			}
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// AppendAuthEvent records a step-up or confirmation on a live session, after its
// earlier events, and moves the session's AuthenticatedAt to the event's time. A zero
// event time is the commit time.
func (s *SessionStorageDriver) AppendAuthEvent(ctx context.Context, sessionID ccc.UUID, event *sessioninfo.AuthEvent) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.authEvents == nil {
		return errors.New("auth events are not configured: attach WithAuthEvents")
	}
	if event.Method == "" {
		return httpio.NewBadRequestMessage("an auth event needs a method")
	}

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		row, err := txn.ReadRow(ctx, s.sessionTableName, spanner.Key{sessionID.String()}, []string{expiredColumnName})
		if err != nil {
			if spanner.ErrCode(err) == codes.NotFound {
				return httpio.NewNotFoundMessagef("session %q not found", sessionID)
			}

			return errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
		}
		var expired bool
		if err := row.Column(0, &expired); err != nil {
			return errors.Wrap(err, "spanner.Row.Column()")
		}
		if expired {
			return httpio.NewBadRequestMessage("cannot record an auth event on an expired session")
		}

		last := spanner.NewStatement(fmt.Sprintf(`SELECT IFNULL(MAX(Seq), 0) FROM %s WHERE SessionId = @id`, s.authEvents.TableName))
		last.Params["id"] = sessionID.String()
		var seq int64
		if err := txn.Query(ctx, last).Do(func(r *spanner.Row) error { return r.Column(0, &seq) }); err != nil {
			return errors.Wrap(err, "spanner.RowIterator.Do()")
		}

		mutations := []*spanner.Mutation{s.authEventMutation(sessionID, seq+1, event)}
		if s.users {
			mutations = append(mutations, spanner.UpdateMap(s.sessionTableName, map[string]any{idColumn: sessionID.String(), "AuthenticatedAt": commitTime(event.At)}))
		}
		if err := txn.BufferWrite(mutations); err != nil {
			return errors.Wrap(err, "txn.BufferWrite()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}
