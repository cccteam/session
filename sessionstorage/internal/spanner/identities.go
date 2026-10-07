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

// IdentitiesConfig configures identity links for the Spanner driver. It is populated by
// the public sessionstorage package from a validated unit; the driver performs no
// validation of its own.
type IdentitiesConfig struct {
	// TableName is the name of the identities table.
	TableName string
	// Resolve decides an external identity that is not linked yet. It runs inside the
	// account resolution transaction, which retries when Spanner aborts it, so it may
	// run more than once for one sign-in.
	Resolve func(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error)
	// Policy, when set, decides every sign-in once its account is known and committed
	// (see dbtype.PolicyApplies), inside the transaction that inserts the session. Nil
	// allows.
	Policy func(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*dbtype.SignInDecision, error)
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

// querier is what a read needs: a single-use read, a read-only or a read-write
// transaction.
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

// lookupIdentity returns the link for (method, connection, subject), or nil.
func (s *SessionStorageDriver) lookupIdentity(ctx context.Context, q querier, method sessioninfo.AuthMethod, connection, subject string) (*dbtype.SessionIdentity, error) {
	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE Method = @method AND Connection = @connection AND Subject = @subject`,
		identityColumns, s.identities.TableName))
	stmt.Params["method"] = string(method)
	stmt.Params["connection"] = connection
	stmt.Params["subject"] = subject

	identities, err := queryIdentities(ctx, q, stmt)
	if err != nil || len(identities) == 0 {
		return nil, err
	}

	return identities[0], nil
}

// newIdentityLink renders a new link of identity to userID and its insert mutation.
func (s *SessionStorageDriver) newIdentityLink(userID ccc.UUID, identity *sessioninfo.Identity, tenant string, now time.Time) (*dbtype.SessionIdentity, *spanner.Mutation, error) {
	if !dbtype.IsExternal(identity) || identity.Subject == "" {
		return nil, nil, httpio.NewBadRequestMessage("only an external identity with a subject can be linked")
	}

	id, err := ccc.NewUUID()
	if err != nil {
		return nil, nil, errors.Wrap(err, "ccc.NewUUID()")
	}
	link := &dbtype.SessionIdentity{
		ID: id, UserID: userID, Method: identity.Method, Connection: identity.Connection, Subject: identity.Subject,
		Tenant: dbtype.OptionalString(tenant), EmailAtLink: dbtype.OptionalString(identity.Email), CreatedAt: now, LastUsedAt: now,
	}

	return link, spanner.InsertMap(s.identities.TableName, map[string]any{
		idColumn: link.ID, "UserId": link.UserID, "Method": string(link.Method), "Connection": link.Connection, "Subject": link.Subject,
		"Tenant": nullString(link.Tenant), "EmailAtLink": nullString(link.EmailAtLink), "CreatedAt": now, "LastUsedAt": now,
	}), nil
}

// readAccount reads userID's account inside txn; a missing account is NotFound.
func (s *SessionStorageDriver) readAccount(ctx context.Context, txn *spanner.ReadWriteTransaction, userID ccc.UUID) (*dbtype.Account, error) {
	row, err := txn.ReadRow(ctx, s.userTableName, spanner.Key{userID.String()}, []string{usernameColumn, "PasswordHash", "Disabled"})
	if err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return nil, httpio.NewNotFoundMessagef("user id %q does not exist", userID)
		}

		return nil, errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
	}

	var (
		a    dbtype.Account
		hash spanner.NullString
	)
	if err := row.Columns(&a.Username, &hash, &a.Disabled); err != nil {
		return nil, errors.Wrap(err, "spanner.Row.Columns()")
	}
	a.HasPassword = hash.Valid

	return &a, nil
}

// insertAccountSession establishes a session for a request that carries a verified
// identity, in two read-write transactions.
//
// The first resolves an external identity's account (resolveIdentity): a linked
// identity is its account's; an unknown one goes to the account resolver, whose
// Resolution is acted on. The second decides and inserts (decideAndInsert): it reads the
// account, refuses a disabled one, runs the sign-in policy, and inserts the session row
// with its auth events and custom session data. Each commits unless a hook or the
// driver fails: a refusal or a pending outcome commits the hooks' own writes (and the
// account resolution) and writes no session. Because the resolution commits first, the
// policy and the custom session data resolver read the account a sign-in provisioned and
// the rows OnProvisioned wrote, which a buffered Spanner write would hide from them.
//
// req.UserID, req.Username and req.Account are set to the resolved account whatever the
// outcome, once it is known.
func (s *SessionStorageDriver) insertAccountSession(ctx context.Context, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) error {
	if s.identities == nil {
		return dbtype.ErrIdentitiesNotConfigured
	}
	if req.CustomData != nil && s.customData == nil {
		return errors.New("custom session data provided but no custom session data config is attached")
	}

	resolved := *req
	resolved.Account = nil
	defer func() { req.UserID, req.Username, req.Account = resolved.UserID, resolved.Username, resolved.Account }()

	source, tenant := sessioninfo.AccountNamed, ""
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
		// The resolution is committed: an account it linked or provisioned is reported
		// even when the decision fails.
		resolved.Account = &sessioninfo.SignInAccount{ID: resolved.UserID, Username: resolved.Username, Source: source, Tenant: tenant}
	case req.UserID.IsNil():
		return errors.New("a password sign-in names its account in req.UserID")
	}

	return s.decideAndInsert(ctx, id, insertSession, &resolved, source, tenant)
}

// resolveIdentity is the first transaction of insertAccountSession: it resolves req's
// external identity to an account, setting req.UserID (and req.Username and
// req.Account once known), and reports how and the link's tenant. stop is a refusal or a
// pending confirmation, which commits. When two first sign-ins of one identity race,
// the loser's link insert fails on the identities key and the resolution runs once
// more, finding the winner's link.
func (s *SessionStorageDriver) resolveIdentity(
	ctx context.Context, req *sessioninfo.NewSessionRequest,
) (source sessioninfo.AccountSource, tenant string, stop, err error) {
	base := *req
	for attempt := 1; ; attempt++ {
		_, err = s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			// Each attempt starts from the caller's request.
			*req = base
			var err error
			source, tenant, stop, err = s.resolveIdentityIn(ctx, txn, req)

			return err
		})
		switch {
		case err == nil:
			return source, tenant, stop, nil
		case spanner.ErrCode(err) == codes.AlreadyExists && strings.Contains(err.Error(), "SessionUsersByNormalizedUsername"):
			return "", "", nil, httpio.NewConflictMessagef("username %q already exists", req.Username)
		case spanner.ErrCode(err) == codes.AlreadyExists && attempt == 1:
			continue
		default:
			return "", "", nil, errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
		}
	}
}

// resolveIdentityIn resolves req's external identity inside txn: a linked identity is
// its account's (its LastUsedAt is touched); an unknown one goes to the account
// resolver, whose Resolution is acted on (applyResolution).
func (s *SessionStorageDriver) resolveIdentityIn(
	ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest,
) (source sessioninfo.AccountSource, tenant string, stop, err error) {
	now := time.Now()

	link, err := s.lookupIdentity(ctx, txn, req.Identity.Method, req.Identity.Connection, req.Identity.Subject)
	if err != nil {
		return "", "", nil, err
	}
	if link != nil {
		req.UserID = link.UserID
		touch := spanner.UpdateMap(s.identities.TableName, map[string]any{idColumn: link.ID, "LastUsedAt": now})
		if err := txn.BufferWrite([]*spanner.Mutation{touch}); err != nil {
			return "", "", nil, errors.Wrap(err, "txn.BufferWrite()")
		}
		if link.Tenant != nil {
			tenant = *link.Tenant
		}

		return sessioninfo.AccountExistingLink, tenant, nil, nil
	}

	res, err := s.identities.Resolve(ctx, txn, req)
	if err != nil {
		return "", "", nil, errors.Wrap(err, "IdentitiesConfig.Resolve()")
	}

	return s.applyResolution(ctx, txn, req, res, now)
}

// decideAndInsert is the second transaction of insertAccountSession, for req's resolved
// account: it reads the account, sets req.Account, decides the sign-in
// (dbtype.DecideSignIn) and, when it goes ahead, buffers the session row, its auth
// events and its custom session data. A refusal or an MFA wait commits the policy's own
// writes and is returned.
func (s *SessionStorageDriver) decideAndInsert(
	ctx context.Context, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest, source sessioninfo.AccountSource, tenant string,
) error {
	base := *req
	var stop error
	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		// Each attempt starts from the resolved request.
		*req, stop = base, nil

		acct, err := s.readAccount(ctx, txn, req.UserID)
		if err != nil {
			return err
		}
		req.Account = dbtype.SignInAccount(req, acct, source, tenant)

		var policy func(ctx context.Context) (*dbtype.SignInDecision, error)
		if s.identities.Policy != nil {
			policy = func(ctx context.Context) (*dbtype.SignInDecision, error) { return s.identities.Policy(ctx, txn, req) }
		}
		stop, err = dbtype.DecideSignIn(ctx, req, acct, policy)
		switch {
		case err != nil:
			return errors.Wrap(err, "dbtype.DecideSignIn()")
		case stop != nil:
			return nil
		}

		return s.bufferAccountSession(ctx, txn, id, insertSession, req)
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return stop
}

// bufferAccountSession buffers the session row, its first auth event and its custom
// session data for a resolved request.
func (s *SessionStorageDriver) bufferAccountSession(
	ctx context.Context, txn *spanner.ReadWriteTransaction, id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest,
) error {
	row := *insertSession
	row.Username = req.Username
	sessionMutation, err := s.sessionInsertMutation(id, &row, req)
	if err != nil {
		return err
	}
	mutations := append([]*spanner.Mutation{sessionMutation}, s.initialAuthEventMutations(id, req, nil, row.CreatedAt)...)
	if err := txn.BufferWrite(mutations); err != nil {
		return errors.Wrap(err, "txn.BufferWrite()")
	}

	data := req.CustomData
	if data == nil && s.customData != nil && s.customData.Resolver != nil {
		data, err = s.customData.Resolver(ctx, txn, req)
		if err != nil {
			return errors.Wrap(err, "CustomSessionDataConfig.Resolver()")
		}
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
}

// applyResolution acts on the account resolver's answer for an unlinked identity: it
// links or provisions (buffering the writes and setting req.UserID and, for a
// provisioned account, req.Username), and reports how and with which tenant; or it
// returns the pending confirmation or the refusal as stop.
func (s *SessionStorageDriver) applyResolution(
	ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest, res *dbtype.Resolution, now time.Time,
) (source sessioninfo.AccountSource, tenant string, stop, err error) {
	if res == nil {
		res = &dbtype.Resolution{}
	}

	switch res.Outcome {
	case dbtype.RejectIdentity:
		return "", "", dbtype.Refusal(res.Refusal, sessioninfo.RefusedIdentityRejected, dbtype.ErrIdentityRejected, "identity rejected"), nil
	case dbtype.LinkIdentity:
		acct, err := s.readAccount(ctx, txn, res.UserID)
		if err != nil {
			return "", "", nil, err
		}
		if acct.HasPassword && !res.TrustedForLinking {
			return "", "", dbtype.Refusal("", sessioninfo.RefusedIdentityRejected, dbtype.ErrLinkRequiresConfirmation, "identity requires confirmation"), nil
		}
		if err := s.bufferLink(txn, res.UserID, req.Identity, res.Tenant, now); err != nil {
			return "", "", nil, err
		}
		req.UserID = res.UserID

		return sessioninfo.AccountNewLink, res.Tenant, nil, nil
	case dbtype.ProvisionAccount:
		if res.NewUser == nil {
			return "", "", nil, errors.New("the account resolver provisioned no account: Resolution.NewUser is nil")
		}
		user, mutation, err := newUserMutation(s.userTableName, res.NewUser)
		if err != nil {
			return "", "", nil, err
		}
		req.Username = user.Username
		if err := txn.BufferWrite([]*spanner.Mutation{mutation}); err != nil {
			return "", "", nil, errors.Wrap(err, "txn.BufferWrite()")
		}
		if err := s.bufferLink(txn, user.ID, req.Identity, res.Tenant, now); err != nil {
			return "", "", nil, err
		}
		req.UserID = user.ID
		if res.OnProvisioned != nil {
			if err := res.OnProvisioned(ctx, user.ID); err != nil {
				return "", "", nil, errors.Wrap(err, "Resolution.OnProvisioned()")
			}
		}

		return sessioninfo.AccountProvisioned, res.Tenant, nil, nil
	case dbtype.RequireConfirmation:
		acct, err := s.readAccount(ctx, txn, res.UserID)
		if err != nil {
			return "", "", nil, err
		}

		return "", "", &dbtype.PendingSignInError{
			Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(res.UserID), Username: acct.Username, Tenant: res.Tenant,
		}, nil
	default:
		return "", "", nil, errors.Newf("unknown account resolver outcome %d", res.Outcome)
	}
}

// bufferLink buffers a new link of identity to userID.
func (s *SessionStorageDriver) bufferLink(txn *spanner.ReadWriteTransaction, userID ccc.UUID, identity *sessioninfo.Identity, tenant string, now time.Time) error {
	_, mutation, err := s.newIdentityLink(userID, identity, tenant, now)
	if err != nil {
		return err
	}
	if err := txn.BufferWrite([]*spanner.Mutation{mutation}); err != nil {
		return errors.Wrap(err, "txn.BufferWrite()")
	}

	return nil
}

// newUserMutation renders a new account row and its insert mutation.
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

	if s.identities == nil {
		return nil, dbtype.ErrIdentitiesNotConfigured
	}

	link, err := s.lookupIdentity(ctx, s.spanner.Single(), method, connection, subject)
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

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE UserId = @userId ORDER BY CreatedAt, Id`, identityColumns, s.identities.TableName))
	stmt.Params["userId"] = userID.String()

	return queryIdentities(ctx, s.spanner.Single(), stmt)
}

// LinkIdentity links identity to userID outside the sign-in flow. An identity that is
// already linked is a Conflict.
func (s *SessionStorageDriver) LinkIdentity(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*dbtype.SessionIdentity, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.identities == nil {
		return nil, dbtype.ErrIdentitiesNotConfigured
	}

	link, mutation, err := s.newIdentityLink(userID, identity, tenant, time.Now())
	if err != nil {
		return nil, err
	}
	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if spanner.ErrCode(err) == codes.AlreadyExists {
			return nil, httpio.NewConflictMessagef("identity (%s, %q, %q) is already linked", identity.Method, identity.Connection, identity.Subject)
		}

		return nil, errors.Wrap(err, "spanner.Client.Apply()")
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

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		row, err := txn.ReadRow(ctx, s.identities.TableName, spanner.Key{identityID.String()}, []string{"UserId"})
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

		acct, err := s.readAccount(ctx, txn, uid)
		if err != nil {
			return err
		}
		if !acct.HasPassword {
			count := spanner.NewStatement(fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE UserId = @userId`, s.identities.TableName))
			count.Params["userId"] = userID
			var links int64
			if err := txn.Query(ctx, count).Do(func(r *spanner.Row) error { return r.Column(0, &links) }); err != nil {
				return errors.Wrap(err, "spanner.RowIterator.Do()")
			}
			if links <= 1 {
				return httpio.NewConflictMessageWithError(dbtype.ErrLastSignInMethod, "the account has no other means of sign-in")
			}
		}

		if err := txn.BufferWrite([]*spanner.Mutation{spanner.Delete(s.identities.TableName, spanner.Key{identityID.String()})}); err != nil {
			return errors.Wrap(err, "txn.BufferWrite()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
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

	now := time.Now()
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

		// Sessions first: the expiry predicate reads the records while they are still live.
		expire := spanner.NewStatement(fmt.Sprintf(`
			UPDATE %s s
			SET Expired = TRUE, UpdatedAt = @now
			WHERE s.Expired = FALSE AND (s.UserId = @userId OR %s)`, s.sessionTableName, s.heldByLocalActor()))
		expire.Params["userId"] = userID.String()
		expire.Params["now"] = now
		if s.impersonation != nil {
			expire.Params["username"] = username
		}
		if _, err := txn.Update(ctx, expire); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}

		if s.impersonation != nil {
			endRecords := spanner.NewStatement(fmt.Sprintf(`
				UPDATE %s
				SET EndedAt = @now, EndReason = @reason
				WHERE EndedAt IS NULL AND (
					SessionId IN (SELECT Id FROM %s WHERE UserId = @userId)
					OR (ActorUsername = @username AND ActorRealm IS NULL))`, s.impersonation.TableName, s.sessionTableName))
			endRecords.Params["userId"] = userID.String()
			endRecords.Params["username"] = username
			endRecords.Params["now"] = now
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
		if s.accounts {
			mutations = append(mutations, spanner.UpdateMap(s.sessionTableName, map[string]any{idColumn: sessionID.String(), "AuthenticatedAt": event.At}))
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
