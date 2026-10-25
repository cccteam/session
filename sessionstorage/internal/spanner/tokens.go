package spanner

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/go-playground/errors/v5"
	"google.golang.org/api/iterator"
)

// tokenColumns are the tokens table's columns.
const tokenColumns = `Id, TokenHash, Kind, UserId, Outlet, Name, Family, ClientId, CreatedAt, ExpiresAt, LastUsedAt, RevokedAt, RevokedReason`

// tokenRow is a token as the table holds it.
type tokenRow struct {
	ID            string             `spanner:"Id"`
	TokenHash     []byte             `spanner:"TokenHash"`
	Kind          string             `spanner:"Kind"`
	UserID        string             `spanner:"UserId"`
	Outlet        string             `spanner:"Outlet"`
	Name          spanner.NullString `spanner:"Name"`
	Family        spanner.NullString `spanner:"Family"`
	ClientID      spanner.NullString `spanner:"ClientId"`
	CreatedAt     time.Time          `spanner:"CreatedAt"`
	ExpiresAt     time.Time          `spanner:"ExpiresAt"`
	LastUsedAt    spanner.NullTime   `spanner:"LastUsedAt"`
	RevokedAt     spanner.NullTime   `spanner:"RevokedAt"`
	RevokedReason spanner.NullString `spanner:"RevokedReason"`
}

// newTokenRow renders t as the table holds it: created at the commit time, unused and
// not revoked, whatever t carries.
func newTokenRow(t *dbtype.Token) *tokenRow {
	r := &tokenRow{
		ID: t.ID.String(), TokenHash: t.TokenHash, Kind: string(t.Kind), UserID: t.UserID.String(), Outlet: t.Outlet,
		CreatedAt: spanner.CommitTimestamp, ExpiresAt: t.ExpiresAt,
	}
	if t.Name != "" {
		r.Name = spanner.NullString{StringVal: t.Name, Valid: true}
	}
	if t.Family.Valid {
		r.Family = spanner.NullString{StringVal: t.Family.String(), Valid: true}
	}
	if t.ClientID != "" {
		r.ClientID = spanner.NullString{StringVal: t.ClientID, Valid: true}
	}

	return r
}

func (r *tokenRow) token() (*dbtype.Token, error) {
	id, err := ccc.UUIDFromString(r.ID)
	if err != nil {
		return nil, errors.Wrap(err, "ccc.UUIDFromString()")
	}
	userID, err := ccc.UUIDFromString(r.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "ccc.UUIDFromString()")
	}
	t := &dbtype.Token{
		ID: id, TokenHash: r.TokenHash, Kind: dbtype.TokenKind(r.Kind), UserID: userID, Outlet: r.Outlet,
		Name: r.Name.StringVal, ClientID: r.ClientID.StringVal, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
		RevokedReason: dbtype.TokenRevocation(r.RevokedReason.StringVal),
	}
	if r.Family.Valid {
		family, err := ccc.UUIDFromString(r.Family.StringVal)
		if err != nil {
			return nil, errors.Wrap(err, "ccc.UUIDFromString()")
		}
		t.Family = ccc.NullUUIDFromUUID(family)
	}
	if r.LastUsedAt.Valid {
		lastUsedAt := r.LastUsedAt.Time
		t.LastUsedAt = &lastUsedAt
	}
	if r.RevokedAt.Valid {
		revokedAt := r.RevokedAt.Time
		t.RevokedAt = &revokedAt
	}

	return t, nil
}

// SetTokensTableName sets the name of the tokens table.
func (s *SessionStorageDriver) SetTokensTableName(name string) error {
	if err := dbtype.ValidateTableName(name); err != nil {
		return errors.Wrap(err, "dbtype.ValidateTableName()")
	}
	s.tokensTableName = name

	return nil
}

// SetDeviceCodesTableName sets the name of the device codes table.
func (s *SessionStorageDriver) SetDeviceCodesTableName(name string) error {
	if err := dbtype.ValidateTableName(name); err != nil {
		return errors.Wrap(err, "dbtype.ValidateTableName()")
	}
	s.deviceCodesTableName = name

	return nil
}

// rowQuerier runs a query: a read-only transaction or a read-write one.
type rowQuerier interface {
	Query(ctx context.Context, statement spanner.Statement) *spanner.RowIterator
}

// queryTokens runs stmt on q and renders its rows.
func queryTokens(ctx context.Context, q rowQuerier, stmt spanner.Statement) ([]*dbtype.Token, error) {
	iter := q.Query(ctx, stmt)
	defer iter.Stop()

	var tokens []*dbtype.Token
	for {
		row, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return tokens, nil
		}
		if err != nil {
			return nil, errors.Wrap(err, "spanner.RowIterator.Next()")
		}
		var r tokenRow
		if err := row.ToStruct(&r); err != nil {
			return nil, errors.Wrap(err, "spanner.Row.ToStruct()")
		}
		t, err := r.token()
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
}

// errTokenNotLive is a transaction's signal that the token it was given is not live.
var errTokenNotLive = errors.New("no live token")

// tokenMutations renders the insert of each token.
func (s *SessionStorageDriver) tokenMutations(tokens ...*dbtype.Token) ([]*spanner.Mutation, error) {
	mutations := make([]*spanner.Mutation, 0, len(tokens))
	for _, t := range tokens {
		if err := t.Kind.Validate(); err != nil {
			return nil, errors.Wrap(err, "dbtype.TokenKind.Validate()")
		}
		m, err := spanner.InsertStruct(s.tokensTableName, newTokenRow(t))
		if err != nil {
			return nil, errors.Wrap(err, "spanner.InsertStruct()")
		}
		mutations = append(mutations, m)
	}

	return mutations, nil
}

// InsertToken inserts t.
func (s *SessionStorageDriver) InsertToken(ctx context.Context, t *dbtype.Token) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	mutations, err := s.tokenMutations(t)
	if err != nil {
		return err
	}
	if _, err := s.spanner.Apply(ctx, mutations); err != nil {
		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// TokenByHash returns the token holding tokenHash that is live at now: not revoked and
// not expired. Any other is NotFound.
func (s *SessionStorageDriver) TokenByHash(ctx context.Context, tokenHash []byte, now time.Time) (*dbtype.Token, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE TokenHash = @tokenHash AND RevokedAt IS NULL AND ExpiresAt > @now`, tokenColumns, s.tokensTableName))
	stmt.Params["tokenHash"] = tokenHash
	stmt.Params["now"] = now

	tokens, err := queryTokens(ctx, s.spanner.Single(), stmt)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, httpio.NewNotFoundMessage("no live token")
	}

	return tokens[0], nil
}

// tokenByHashIn reads the token holding tokenHash inside txn, whatever its state;
// errTokenNotLive when there is none.
func (s *SessionStorageDriver) tokenByHashIn(ctx context.Context, txn *spanner.ReadWriteTransaction, tokenHash []byte) (*dbtype.Token, error) {
	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE TokenHash = @tokenHash`, tokenColumns, s.tokensTableName))
	stmt.Params["tokenHash"] = tokenHash

	tokens, err := queryTokens(ctx, txn, stmt)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, errTokenNotLive
	}

	return tokens[0], nil
}

// TokensByUser lists the tokens of userID that are live at now, newest first.
func (s *SessionStorageDriver) TokensByUser(ctx context.Context, userID ccc.UUID, now time.Time) ([]*dbtype.Token, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE UserId = @userId AND RevokedAt IS NULL AND ExpiresAt > @now ORDER BY CreatedAt DESC, Id`, tokenColumns, s.tokensTableName))
	stmt.Params["userId"] = userID.String()
	stmt.Params["now"] = now

	return queryTokens(ctx, s.spanner.Single(), stmt)
}

// TouchToken moves the LastUsedAt of the live token id to the commit time. A token
// that is not live is left as it is.
func (s *SessionStorageDriver) TouchToken(ctx context.Context, id ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET LastUsedAt = PENDING_COMMIT_TIMESTAMP() WHERE Id = @id AND RevokedAt IS NULL AND ExpiresAt > @now`, s.tokensTableName))
		stmt.Params["id"] = id.String()
		stmt.Params["now"] = now
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

// revokeIn revokes, inside txn at the commit time, the live tokens whose column holds
// value, and reports how many it revoked.
func (s *SessionStorageDriver) revokeIn(ctx context.Context, txn *spanner.ReadWriteTransaction, column string, value any, reason dbtype.TokenRevocation) (int64, error) {
	if err := reason.Validate(); err != nil {
		return 0, errors.Wrap(err, "dbtype.TokenRevocation.Validate()")
	}
	stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET RevokedAt = PENDING_COMMIT_TIMESTAMP(), RevokedReason = @reason WHERE %s = @value AND RevokedAt IS NULL`, s.tokensTableName, column))
	stmt.Params["value"] = value
	stmt.Params["reason"] = string(reason)

	n, err := txn.Update(ctx, stmt)
	if err != nil {
		return 0, errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
	}

	return n, nil
}

// RevokeUserToken revokes the live token id of userID, at the commit time, with
// reason: the token alone, or its whole family when it has one, so revoking a device
// grant's refresh token revokes its access token with it. A token that is not live,
// or is not the user's, is NotFound.
func (s *SessionStorageDriver) RevokeUserToken(ctx context.Context, userID, id ccc.UUID, now time.Time, reason dbtype.TokenRevocation) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE Id = @id AND UserId = @userId AND RevokedAt IS NULL AND ExpiresAt > @now`, tokenColumns, s.tokensTableName))
		stmt.Params["id"] = id.String()
		stmt.Params["userId"] = userID.String()
		stmt.Params["now"] = now
		tokens, err := queryTokens(ctx, txn, stmt)
		if err != nil {
			return err
		}
		if len(tokens) == 0 {
			return errTokenNotLive
		}
		column, value := idColumn, id.String()
		if t := tokens[0]; t.Family.Valid {
			column, value = "Family", t.Family.String()
		}
		if _, err := s.revokeIn(ctx, txn, column, value, reason); err != nil {
			return err
		}

		return nil
	})
	if errors.Is(err, errTokenNotLive) {
		return httpio.NewNotFoundMessage("no live token")
	}
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// RevokeUserTokens revokes every live token of userID, at the commit time, with reason.
func (s *SessionStorageDriver) RevokeUserTokens(ctx context.Context, userID ccc.UUID, reason dbtype.TokenRevocation) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		_, err := s.revokeIn(ctx, txn, "UserId", userID.String(), reason)

		return err
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// ExchangeRefreshToken rotates the refresh token holding tokenHash, in one
// transaction: the token is revoked as rotated and access and refresh are inserted in
// its family, as its user, for its outlet and client (the driver fills those fields
// of the two from the token). A token that is not a live refresh token is NotFound.
// A refresh token already rotated is a reuse: the whole family is revoked, that is
// committed, and the exchange returns dbtype.ErrTokenReuse.
func (s *SessionStorageDriver) ExchangeRefreshToken(ctx context.Context, tokenHash []byte, now time.Time, access, refresh *dbtype.Token) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var reused bool
	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		reused = false
		old, err := s.tokenByHashIn(ctx, txn, tokenHash)
		if err != nil {
			return err
		}
		if old.Kind != dbtype.TokenRefresh || !old.ExpiresAt.After(now) {
			return errTokenNotLive
		}
		if old.RevokedAt != nil {
			if old.RevokedReason != dbtype.TokenRevokedRotated || !old.Family.Valid {
				return errTokenNotLive
			}
			if _, err := s.revokeIn(ctx, txn, "Family", old.Family.String(), dbtype.TokenRevokedReuse); err != nil {
				return err
			}
			reused = true

			return nil
		}
		// The rotation revokes the pair presented: the refresh token and, with it,
		// every live token of its family, so one pair is live per family.
		column, key := idColumn, old.ID.String()
		if old.Family.Valid {
			column, key = "Family", old.Family.String()
		}
		n, err := s.revokeIn(ctx, txn, column, key, dbtype.TokenRevokedRotated)
		if err != nil {
			return err
		}
		if n == 0 {
			return errTokenNotLive
		}
		for _, t := range []*dbtype.Token{access, refresh} {
			t.UserID, t.Outlet, t.ClientID, t.Family = old.UserID, old.Outlet, old.ClientID, old.Family
		}
		mutations, err := s.tokenMutations(access, refresh)
		if err != nil {
			return err
		}
		if err := txn.BufferWrite(mutations); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.BufferWrite()")
		}

		return nil
	})
	switch {
	case errors.Is(err, errTokenNotLive):
		return httpio.NewNotFoundMessage("no live refresh token")
	case err != nil:
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	case reused:
		return dbtype.ErrTokenReuse
	}

	return nil
}

// deviceCodeColumns are the device codes table's columns.
const deviceCodeColumns = `Id, DeviceCodeHash, UserCode, ClientId, Outlet, UserId, CreatedAt, ExpiresAt, ApprovedAt, DeniedAt, LastPolledAt, ConsumedAt`

// deviceCodeRow is a device code as the table holds it.
type deviceCodeRow struct {
	ID             string             `spanner:"Id"`
	DeviceCodeHash []byte             `spanner:"DeviceCodeHash"`
	UserCode       string             `spanner:"UserCode"`
	ClientID       string             `spanner:"ClientId"`
	Outlet         string             `spanner:"Outlet"`
	UserID         spanner.NullString `spanner:"UserId"`
	CreatedAt      time.Time          `spanner:"CreatedAt"`
	ExpiresAt      time.Time          `spanner:"ExpiresAt"`
	ApprovedAt     spanner.NullTime   `spanner:"ApprovedAt"`
	DeniedAt       spanner.NullTime   `spanner:"DeniedAt"`
	LastPolledAt   spanner.NullTime   `spanner:"LastPolledAt"`
	ConsumedAt     spanner.NullTime   `spanner:"ConsumedAt"`
}

func nullTimePtr(t spanner.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time

	return &v
}

func (r *deviceCodeRow) deviceCode() (*dbtype.DeviceCode, error) {
	id, err := ccc.UUIDFromString(r.ID)
	if err != nil {
		return nil, errors.Wrap(err, "ccc.UUIDFromString()")
	}
	d := &dbtype.DeviceCode{
		ID: id, DeviceCodeHash: r.DeviceCodeHash, UserCode: r.UserCode, ClientID: r.ClientID, Outlet: r.Outlet,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
		ApprovedAt: nullTimePtr(r.ApprovedAt), DeniedAt: nullTimePtr(r.DeniedAt), LastPolledAt: nullTimePtr(r.LastPolledAt), ConsumedAt: nullTimePtr(r.ConsumedAt),
	}
	if r.UserID.Valid {
		userID, err := ccc.UUIDFromString(r.UserID.StringVal)
		if err != nil {
			return nil, errors.Wrap(err, "ccc.UUIDFromString()")
		}
		d.UserID = ccc.NullUUIDFromUUID(userID)
	}

	return d, nil
}

// InsertDeviceCode inserts d: created at the commit time and pending, whatever d
// carries.
func (s *SessionStorageDriver) InsertDeviceCode(ctx context.Context, d *dbtype.DeviceCode) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	r := &deviceCodeRow{
		ID: d.ID.String(), DeviceCodeHash: d.DeviceCodeHash, UserCode: d.UserCode, ClientID: d.ClientID, Outlet: d.Outlet,
		CreatedAt: spanner.CommitTimestamp, ExpiresAt: d.ExpiresAt,
	}
	m, err := spanner.InsertStruct(s.deviceCodesTableName, r)
	if err != nil {
		return errors.Wrap(err, "spanner.InsertStruct()")
	}
	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{m}); err != nil {
		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// queryDeviceCodes runs stmt on q and renders its rows.
func queryDeviceCodes(ctx context.Context, q rowQuerier, stmt spanner.Statement) ([]*dbtype.DeviceCode, error) {
	iter := q.Query(ctx, stmt)
	defer iter.Stop()

	var codes []*dbtype.DeviceCode
	for {
		row, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return codes, nil
		}
		if err != nil {
			return nil, errors.Wrap(err, "spanner.RowIterator.Next()")
		}
		var r deviceCodeRow
		if err := row.ToStruct(&r); err != nil {
			return nil, errors.Wrap(err, "spanner.Row.ToStruct()")
		}
		d, err := r.deviceCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, d)
	}
}

// errDeviceCodeNotPending is a transaction's signal that the device code it was given
// is not there or no longer pending.
var errDeviceCodeNotPending = errors.New("no pending device code")

// DeviceCodeByUserCode returns the device authorization the person's userCode names
// that is pending at now: not decided, not consumed, not expired. Any other is NotFound.
func (s *SessionStorageDriver) DeviceCodeByUserCode(ctx context.Context, userCode string, now time.Time) (*dbtype.DeviceCode, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(
		`SELECT %s FROM %s WHERE UserCode = @userCode AND ApprovedAt IS NULL AND DeniedAt IS NULL AND ConsumedAt IS NULL AND ExpiresAt > @now`,
		deviceCodeColumns, s.deviceCodesTableName,
	))
	stmt.Params["userCode"] = userCode
	stmt.Params["now"] = now

	codes, err := queryDeviceCodes(ctx, s.spanner.Single(), stmt)
	if err != nil {
		return nil, err
	}
	if len(codes) == 0 {
		return nil, httpio.NewNotFoundMessage("no pending device code")
	}

	return codes[0], nil
}

// decideDeviceCode writes the decision on the pending device code id, in a transaction
// of its own: set is the column list the update sets. A code that is not pending is
// NotFound, so one decision stands.
func (s *SessionStorageDriver) decideDeviceCode(ctx context.Context, id ccc.UUID, now time.Time, set string, params map[string]any) error {
	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET %s WHERE Id = @id AND ApprovedAt IS NULL AND DeniedAt IS NULL AND ConsumedAt IS NULL AND ExpiresAt > @now`, s.deviceCodesTableName, set))
		stmt.Params["id"] = id.String()
		stmt.Params["now"] = now
		for k, v := range params {
			stmt.Params[k] = v
		}
		n, err := txn.Update(ctx, stmt)
		if err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}
		if n == 0 {
			return errDeviceCodeNotPending
		}

		return nil
	})
	if errors.Is(err, errDeviceCodeNotPending) {
		return httpio.NewNotFoundMessage("no pending device code")
	}
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// ApproveDeviceCode records that userID approved the pending device code id, at the
// commit time. A code that is not pending is NotFound.
func (s *SessionStorageDriver) ApproveDeviceCode(ctx context.Context, id, userID ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return s.decideDeviceCode(ctx, id, now, `ApprovedAt = PENDING_COMMIT_TIMESTAMP(), UserId = @userId`, map[string]any{"userId": userID.String()})
}

// DenyDeviceCode records that the person denied the pending device code id, at the
// commit time. A code that is not pending is NotFound.
func (s *SessionStorageDriver) DenyDeviceCode(ctx context.Context, id ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return s.decideDeviceCode(ctx, id, now, `DeniedAt = PENDING_COMMIT_TIMESTAMP()`, nil)
}

// RedeemDeviceCode is the client's poll of the device code holding deviceCodeHash, in
// one transaction. An approved code is consumed, once, and access and refresh are
// inserted as the approving user's, for the code's outlet and client (the driver
// fills those fields of the two from the code), and the status is approved; a pending
// code polled before interval passed since the last poll is slow_down and nothing is
// written, otherwise the poll is recorded and the status is pending; a denied or
// expired code is denied or expired. A code that is not there or was consumed is
// NotFound.
func (s *SessionStorageDriver) RedeemDeviceCode(
	ctx context.Context, deviceCodeHash []byte, now time.Time, interval time.Duration, access, refresh *dbtype.Token,
) (*dbtype.DeviceCode, dbtype.DeviceCodeStatus, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var code *dbtype.DeviceCode
	var status dbtype.DeviceCodeStatus
	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE DeviceCodeHash = @hash`, deviceCodeColumns, s.deviceCodesTableName))
		stmt.Params["hash"] = deviceCodeHash
		codes, err := queryDeviceCodes(ctx, txn, stmt)
		if err != nil {
			return err
		}
		if len(codes) == 0 || codes[0].ConsumedAt != nil {
			return errDeviceCodeNotPending
		}
		code = codes[0]
		status, err = s.redeemIn(ctx, txn, code, now, interval, access, refresh)

		return err
	})
	switch {
	case errors.Is(err, errDeviceCodeNotPending):
		return nil, "", httpio.NewNotFoundMessage("no device code to redeem")
	case err != nil:
		return nil, "", errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return code, status, nil
}

// redeemIn decides the poll of code inside txn and writes what it decides.
func (s *SessionStorageDriver) redeemIn(
	ctx context.Context, txn *spanner.ReadWriteTransaction, code *dbtype.DeviceCode, now time.Time, interval time.Duration, access, refresh *dbtype.Token,
) (dbtype.DeviceCodeStatus, error) {
	switch {
	case !code.ExpiresAt.After(now):
		return dbtype.DeviceExpired, nil
	case code.DeniedAt != nil:
		return dbtype.DeviceDenied, nil
	case code.ApprovedAt == nil:
		if code.LastPolledAt != nil && now.Before(code.LastPolledAt.Add(interval)) {
			return dbtype.DeviceSlowDown, nil
		}
		stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET LastPolledAt = PENDING_COMMIT_TIMESTAMP() WHERE Id = @id`, s.deviceCodesTableName))
		stmt.Params["id"] = code.ID.String()
		if _, err := txn.Update(ctx, stmt); err != nil {
			return "", errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}

		return dbtype.DevicePending, nil
	}

	stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET ConsumedAt = PENDING_COMMIT_TIMESTAMP() WHERE Id = @id AND ConsumedAt IS NULL`, s.deviceCodesTableName))
	stmt.Params["id"] = code.ID.String()
	n, err := txn.Update(ctx, stmt)
	if err != nil {
		return "", errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
	}
	if n == 0 {
		return "", errDeviceCodeNotPending
	}
	for _, t := range []*dbtype.Token{access, refresh} {
		t.UserID, t.Outlet, t.ClientID = code.UserID.UUID, code.Outlet, code.ClientID
	}
	mutations, err := s.tokenMutations(access, refresh)
	if err != nil {
		return "", err
	}
	if err := txn.BufferWrite(mutations); err != nil {
		return "", errors.Wrap(err, "spanner.ReadWriteTransaction.BufferWrite()")
	}

	return dbtype.DeviceApproved, nil
}

// TokenState reads the token holding tokenHash whatever its state, revoked or expired
// included; NotFound when there is none. It serves the conformance suite's look at a
// row the live reads no longer return.
func (s *SessionStorageDriver) TokenState(ctx context.Context, tokenHash []byte) (*dbtype.Token, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE TokenHash = @tokenHash`, tokenColumns, s.tokensTableName))
	stmt.Params["tokenHash"] = tokenHash
	tokens, err := queryTokens(ctx, s.spanner.Single(), stmt)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, httpio.NewNotFoundMessage("no token")
	}

	return tokens[0], nil
}

// DeviceCodeState reads the device code holding deviceCodeHash whatever its state;
// NotFound when there is none.
func (s *SessionStorageDriver) DeviceCodeState(ctx context.Context, deviceCodeHash []byte) (*dbtype.DeviceCode, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE DeviceCodeHash = @hash`, deviceCodeColumns, s.deviceCodesTableName))
	stmt.Params["hash"] = deviceCodeHash
	codes, err := queryDeviceCodes(ctx, s.spanner.Single(), stmt)
	if err != nil {
		return nil, err
	}
	if len(codes) == 0 {
		return nil, httpio.NewNotFoundMessage("no device code")
	}

	return codes[0], nil
}
