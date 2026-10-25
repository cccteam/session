package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// tokenColumns are the tokens table's columns, in tokenRow's order.
const tokenColumns = `"Id", "TokenHash", "Kind", "UserId", "Outlet", "Name", "Family", "ClientId", "CreatedAt", "ExpiresAt", "LastUsedAt", "RevokedAt", "RevokedReason"`

// tokenRow is a token as the table holds it.
type tokenRow struct {
	ID            ccc.UUID   `db:"Id"`
	TokenHash     []byte     `db:"TokenHash"`
	Kind          string     `db:"Kind"`
	UserID        ccc.UUID   `db:"UserId"`
	Outlet        string     `db:"Outlet"`
	Name          *string    `db:"Name"`
	Family        *ccc.UUID  `db:"Family"`
	ClientID      *string    `db:"ClientId"`
	CreatedAt     time.Time  `db:"CreatedAt"`
	ExpiresAt     time.Time  `db:"ExpiresAt"`
	LastUsedAt    *time.Time `db:"LastUsedAt"`
	RevokedAt     *time.Time `db:"RevokedAt"`
	RevokedReason *string    `db:"RevokedReason"`
}

func (r *tokenRow) token() *dbtype.Token {
	t := &dbtype.Token{
		ID: r.ID, TokenHash: r.TokenHash, Kind: dbtype.TokenKind(r.Kind), UserID: r.UserID, Outlet: r.Outlet,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt,
	}
	if r.Name != nil {
		t.Name = *r.Name
	}
	if r.Family != nil {
		t.Family = ccc.NullUUIDFromUUID(*r.Family)
	}
	if r.ClientID != nil {
		t.ClientID = *r.ClientID
	}
	if r.RevokedReason != nil {
		t.RevokedReason = dbtype.TokenRevocation(*r.RevokedReason)
	}

	return t
}

func (s *SessionStorageDriver) tokensTable() string {
	return pgx.Identifier{s.tokensTableName}.Sanitize()
}

func (s *SessionStorageDriver) deviceCodesTable() string {
	return pgx.Identifier{s.deviceCodesTableName}.Sanitize()
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

// insertToken inserts each token through q: created at the database's time, unused and
// not revoked, whatever it carries.
func (s *SessionStorageDriver) insertTokens(ctx context.Context, q execer, tokens ...*dbtype.Token) error {
	query := fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9, NULL, NULL, NULL)`, s.tokensTable(), tokenColumns)
	for _, t := range tokens {
		if err := t.Kind.Validate(); err != nil {
			return errors.Wrap(err, "dbtype.TokenKind.Validate()")
		}
		var family *ccc.UUID
		if t.Family.Valid {
			family = &t.Family.UUID
		}
		if _, err := q.Exec(ctx, query, t.ID, t.TokenHash, string(t.Kind), t.UserID, t.Outlet, dbtype.OptionalString(t.Name), family, dbtype.OptionalString(t.ClientID), t.ExpiresAt); err != nil {
			return errors.Wrap(err, "Exec()")
		}
	}

	return nil
}

// InsertToken inserts t.
func (s *SessionStorageDriver) InsertToken(ctx context.Context, t *dbtype.Token) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return s.insertTokens(ctx, s.conn, t)
}

// queryTokens runs query on q and renders its rows.
func queryTokens(ctx context.Context, q pgxscan.Querier, query string, args ...any) ([]*dbtype.Token, error) {
	var rows []*tokenRow
	if err := pgxscan.Select(ctx, q, &rows, query, args...); err != nil {
		return nil, errors.Wrap(err, "pgxscan.Select()")
	}
	tokens := make([]*dbtype.Token, len(rows))
	for i, r := range rows {
		tokens[i] = r.token()
	}

	return tokens, nil
}

// TokenByHash returns the token holding tokenHash that is live at now: not revoked and
// not expired. Any other is NotFound.
func (s *SessionStorageDriver) TokenByHash(ctx context.Context, tokenHash []byte, now time.Time) (*dbtype.Token, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "TokenHash" = $1 AND "RevokedAt" IS NULL AND "ExpiresAt" > $2`, tokenColumns, s.tokensTable())
	tokens, err := queryTokens(ctx, s.conn, query, tokenHash, now)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, httpio.NewNotFoundMessage("no live token")
	}

	return tokens[0], nil
}

// TokensByUser lists the tokens of userID that are live at now, newest first.
func (s *SessionStorageDriver) TokensByUser(ctx context.Context, userID ccc.UUID, now time.Time) ([]*dbtype.Token, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "UserId" = $1 AND "RevokedAt" IS NULL AND "ExpiresAt" > $2 ORDER BY "CreatedAt" DESC, "Id"`, tokenColumns, s.tokensTable())

	return queryTokens(ctx, s.conn, query, userID, now)
}

// TouchToken moves the LastUsedAt of the live token id to the database's time. A
// token that is not live is left as it is.
func (s *SessionStorageDriver) TouchToken(ctx context.Context, id ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`UPDATE %s SET "LastUsedAt" = now() WHERE "Id" = $1 AND "RevokedAt" IS NULL AND "ExpiresAt" > $2`, s.tokensTable())
	if _, err := s.conn.Exec(ctx, query, id, now); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}

// revokeIn revokes, through q at the database's time, the live tokens whose column
// holds value.
func (s *SessionStorageDriver) revokeIn(ctx context.Context, q execer, column string, value any, reason dbtype.TokenRevocation) error {
	if err := reason.Validate(); err != nil {
		return errors.Wrap(err, "dbtype.TokenRevocation.Validate()")
	}
	query := fmt.Sprintf(`UPDATE %s SET "RevokedAt" = now(), "RevokedReason" = $2 WHERE %s = $1 AND "RevokedAt" IS NULL`, s.tokensTable(), column)
	if _, err := q.Exec(ctx, query, value, string(reason)); err != nil {
		return errors.Wrap(err, "Exec()")
	}

	return nil
}

// RevokeUserToken revokes the live token id of userID, at the database's time, with
// reason: the token alone, or its whole family when it has one, so revoking a device
// grant's refresh token revokes its access token with it. A token that is not live,
// or is not the user's, is NotFound.
func (s *SessionStorageDriver) RevokeUserToken(ctx context.Context, userID, id ccc.UUID, now time.Time, reason dbtype.TokenRevocation) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return s.Transact(ctx, func(ctx context.Context, tx pgx.Tx) error {
		query := fmt.Sprintf(`SELECT %s FROM %s WHERE "Id" = $1 AND "UserId" = $2 AND "RevokedAt" IS NULL AND "ExpiresAt" > $3 FOR UPDATE`, tokenColumns, s.tokensTable())
		tokens, err := queryTokens(ctx, tx, query, id, userID, now)
		if err != nil {
			return err
		}
		if len(tokens) == 0 {
			return httpio.NewNotFoundMessage("no live token")
		}
		column, value := `"Id"`, any(id)
		if t := tokens[0]; t.Family.Valid {
			column, value = `"Family"`, any(t.Family.UUID)
		}
		if err := s.revokeIn(ctx, tx, column, value, reason); err != nil {
			return err
		}

		return nil
	})
}

// RevokeUserTokens revokes every live token of userID, at the database's time, with
// reason.
func (s *SessionStorageDriver) RevokeUserTokens(ctx context.Context, userID ccc.UUID, reason dbtype.TokenRevocation) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := s.revokeIn(ctx, s.conn, `"UserId"`, userID, reason); err != nil {
		return err
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
	err := s.Transact(ctx, func(ctx context.Context, tx pgx.Tx) error {
		reused = false
		query := fmt.Sprintf(`SELECT %s FROM %s WHERE "TokenHash" = $1 FOR UPDATE`, tokenColumns, s.tokensTable())
		tokens, err := queryTokens(ctx, tx, query, tokenHash)
		if err != nil {
			return err
		}
		if len(tokens) == 0 || tokens[0].Kind != dbtype.TokenRefresh || !tokens[0].ExpiresAt.After(now) {
			return httpio.NewNotFoundMessage("no live refresh token")
		}
		old := tokens[0]
		if old.RevokedAt != nil {
			if old.RevokedReason != dbtype.TokenRevokedRotated || !old.Family.Valid {
				return httpio.NewNotFoundMessage("no live refresh token")
			}
			if err := s.revokeIn(ctx, tx, `"Family"`, old.Family.UUID, dbtype.TokenRevokedReuse); err != nil {
				return err
			}
			reused = true

			return nil
		}
		// The rotation revokes the pair presented: the refresh token and, with it,
		// every live token of its family, so one pair is live per family.
		column, key := `"Id"`, old.ID
		if old.Family.Valid {
			column, key = `"Family"`, old.Family.UUID
		}
		if err := s.revokeIn(ctx, tx, column, key, dbtype.TokenRevokedRotated); err != nil {
			return err
		}
		for _, t := range []*dbtype.Token{access, refresh} {
			t.UserID, t.Outlet, t.ClientID, t.Family = old.UserID, old.Outlet, old.ClientID, old.Family
		}

		return s.insertTokens(ctx, tx, access, refresh)
	})
	if err != nil {
		return err
	}
	if reused {
		return dbtype.ErrTokenReuse
	}

	return nil
}

// deviceCodeColumns are the device codes table's columns, in deviceCodeRow's order.
const deviceCodeColumns = `"Id", "DeviceCodeHash", "UserCode", "ClientId", "Outlet", "UserId", "CreatedAt", "ExpiresAt", "ApprovedAt", "DeniedAt", "LastPolledAt", "ConsumedAt"`

// deviceCodeRow is a device code as the table holds it.
type deviceCodeRow struct {
	ID             ccc.UUID   `db:"Id"`
	DeviceCodeHash []byte     `db:"DeviceCodeHash"`
	UserCode       string     `db:"UserCode"`
	ClientID       string     `db:"ClientId"`
	Outlet         string     `db:"Outlet"`
	UserID         *ccc.UUID  `db:"UserId"`
	CreatedAt      time.Time  `db:"CreatedAt"`
	ExpiresAt      time.Time  `db:"ExpiresAt"`
	ApprovedAt     *time.Time `db:"ApprovedAt"`
	DeniedAt       *time.Time `db:"DeniedAt"`
	LastPolledAt   *time.Time `db:"LastPolledAt"`
	ConsumedAt     *time.Time `db:"ConsumedAt"`
}

func (r *deviceCodeRow) deviceCode() *dbtype.DeviceCode {
	d := &dbtype.DeviceCode{
		ID: r.ID, DeviceCodeHash: r.DeviceCodeHash, UserCode: r.UserCode, ClientID: r.ClientID, Outlet: r.Outlet,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, ApprovedAt: r.ApprovedAt, DeniedAt: r.DeniedAt, LastPolledAt: r.LastPolledAt, ConsumedAt: r.ConsumedAt,
	}
	if r.UserID != nil {
		d.UserID = ccc.NullUUIDFromUUID(*r.UserID)
	}

	return d
}

// InsertDeviceCode inserts d: created at the database's time and pending, whatever d
// carries.
func (s *SessionStorageDriver) InsertDeviceCode(ctx context.Context, d *dbtype.DeviceCode) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1, $2, $3, $4, $5, NULL, now(), $6, NULL, NULL, NULL, NULL)`, s.deviceCodesTable(), deviceCodeColumns)
	if _, err := s.conn.Exec(ctx, query, d.ID, d.DeviceCodeHash, d.UserCode, d.ClientID, d.Outlet, d.ExpiresAt); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}

// queryDeviceCodes runs query on q and renders its rows.
func queryDeviceCodes(ctx context.Context, q pgxscan.Querier, query string, args ...any) ([]*dbtype.DeviceCode, error) {
	var rows []*deviceCodeRow
	if err := pgxscan.Select(ctx, q, &rows, query, args...); err != nil {
		return nil, errors.Wrap(err, "pgxscan.Select()")
	}
	codes := make([]*dbtype.DeviceCode, len(rows))
	for i, r := range rows {
		codes[i] = r.deviceCode()
	}

	return codes, nil
}

// pendingDeviceCode is the condition of a device code row that still waits for the
// person: $N names the parameter that holds now.
func pendingDeviceCode(nowParam string) string {
	return fmt.Sprintf(`"ApprovedAt" IS NULL AND "DeniedAt" IS NULL AND "ConsumedAt" IS NULL AND "ExpiresAt" > %s`, nowParam)
}

// DeviceCodeByUserCode returns the device authorization the person's userCode names
// that is pending at now: not decided, not consumed, not expired. Any other is NotFound.
func (s *SessionStorageDriver) DeviceCodeByUserCode(ctx context.Context, userCode string, now time.Time) (*dbtype.DeviceCode, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "UserCode" = $1 AND %s`, deviceCodeColumns, s.deviceCodesTable(), pendingDeviceCode("$2"))
	codes, err := queryDeviceCodes(ctx, s.conn, query, userCode, now)
	if err != nil {
		return nil, err
	}
	if len(codes) == 0 {
		return nil, httpio.NewNotFoundMessage("no pending device code")
	}

	return codes[0], nil
}

// ApproveDeviceCode records that userID approved the pending device code id, at the
// database's time. A code that is not pending is NotFound, so one decision stands.
func (s *SessionStorageDriver) ApproveDeviceCode(ctx context.Context, id, userID ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`UPDATE %s SET "ApprovedAt" = now(), "UserId" = $3 WHERE "Id" = $1 AND %s`, s.deviceCodesTable(), pendingDeviceCode("$2"))
	tag, err := s.conn.Exec(ctx, query, id, now, userID)
	if err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}
	if tag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessage("no pending device code")
	}

	return nil
}

// DenyDeviceCode records that the person denied the pending device code id, at the
// database's time. A code that is not pending is NotFound.
func (s *SessionStorageDriver) DenyDeviceCode(ctx context.Context, id ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`UPDATE %s SET "DeniedAt" = now() WHERE "Id" = $1 AND %s`, s.deviceCodesTable(), pendingDeviceCode("$2"))
	tag, err := s.conn.Exec(ctx, query, id, now)
	if err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}
	if tag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessage("no pending device code")
	}

	return nil
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
	err := s.Transact(ctx, func(ctx context.Context, tx pgx.Tx) error {
		query := fmt.Sprintf(`SELECT %s FROM %s WHERE "DeviceCodeHash" = $1 FOR UPDATE`, deviceCodeColumns, s.deviceCodesTable())
		codes, err := queryDeviceCodes(ctx, tx, query, deviceCodeHash)
		if err != nil {
			return err
		}
		if len(codes) == 0 || codes[0].ConsumedAt != nil {
			return httpio.NewNotFoundMessage("no device code to redeem")
		}
		code = codes[0]
		status, err = s.redeemIn(ctx, tx, code, now, interval, access, refresh)

		return err
	})
	if err != nil {
		return nil, "", err
	}

	return code, status, nil
}

// redeemIn decides the poll of code inside tx and writes what it decides.
func (s *SessionStorageDriver) redeemIn(
	ctx context.Context, tx pgx.Tx, code *dbtype.DeviceCode, now time.Time, interval time.Duration, access, refresh *dbtype.Token,
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
		if _, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET "LastPolledAt" = now() WHERE "Id" = $1`, s.deviceCodesTable()), code.ID); err != nil {
			return "", errors.Wrap(err, "pgx.Tx.Exec()")
		}

		return dbtype.DevicePending, nil
	}

	tag, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET "ConsumedAt" = now() WHERE "Id" = $1 AND "ConsumedAt" IS NULL`, s.deviceCodesTable()), code.ID)
	if err != nil {
		return "", errors.Wrap(err, "pgx.Tx.Exec()")
	}
	if tag.RowsAffected() == 0 {
		return "", httpio.NewNotFoundMessage("no device code to redeem")
	}
	for _, t := range []*dbtype.Token{access, refresh} {
		t.UserID, t.Outlet, t.ClientID = code.UserID.UUID, code.Outlet, code.ClientID
	}
	if err := s.insertTokens(ctx, tx, access, refresh); err != nil {
		return "", err
	}

	return dbtype.DeviceApproved, nil
}

// TokenState reads the token holding tokenHash whatever its state, revoked or expired
// included; NotFound when there is none. It serves the conformance suite's look at a
// row the live reads no longer return.
func (s *SessionStorageDriver) TokenState(ctx context.Context, tokenHash []byte) (*dbtype.Token, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	tokens, err := queryTokens(ctx, s.conn, fmt.Sprintf(`SELECT %s FROM %s WHERE "TokenHash" = $1`, tokenColumns, s.tokensTable()), tokenHash)
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

	codes, err := queryDeviceCodes(ctx, s.conn, fmt.Sprintf(`SELECT %s FROM %s WHERE "DeviceCodeHash" = $1`, deviceCodeColumns, s.deviceCodesTable()), deviceCodeHash)
	if err != nil {
		return nil, err
	}
	if len(codes) == 0 {
		return nil, httpio.NewNotFoundMessage("no device code")
	}

	return codes[0], nil
}
