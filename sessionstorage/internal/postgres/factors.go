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

// factorCodeColumns are the factor codes table's columns, in factorCodeRow's order.
const factorCodeColumns = `"Id", "PendingId", "Email", "CodeHash", "Attempts", "CreatedAt", "ExpiresAt", "ConsumedAt"`

// factorCodeRow is a factor code as the table holds it.
type factorCodeRow struct {
	ID         ccc.UUID   `db:"Id"`
	PendingID  ccc.UUID   `db:"PendingId"`
	Email      string     `db:"Email"`
	CodeHash   []byte     `db:"CodeHash"`
	Attempts   int        `db:"Attempts"`
	CreatedAt  time.Time  `db:"CreatedAt"`
	ExpiresAt  time.Time  `db:"ExpiresAt"`
	ConsumedAt *time.Time `db:"ConsumedAt"`
}

func (r *factorCodeRow) code() *dbtype.FactorCode {
	return &dbtype.FactorCode{
		ID: r.ID, PendingID: r.PendingID, Email: r.Email, CodeHash: r.CodeHash, Attempts: r.Attempts,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, ConsumedAt: r.ConsumedAt,
	}
}

// trustedDeviceColumns are the trusted devices table's columns, in trustedDeviceRow's
// order.
const trustedDeviceColumns = `"Id", "UserId", "TokenHash", "CreatedAt", "ExpiresAt", "LastUsedAt", "RevokedAt"`

// trustedDeviceRow is a trusted device as the table holds it.
type trustedDeviceRow struct {
	ID         ccc.UUID   `db:"Id"`
	UserID     ccc.UUID   `db:"UserId"`
	TokenHash  []byte     `db:"TokenHash"`
	CreatedAt  time.Time  `db:"CreatedAt"`
	ExpiresAt  time.Time  `db:"ExpiresAt"`
	LastUsedAt *time.Time `db:"LastUsedAt"`
	RevokedAt  *time.Time `db:"RevokedAt"`
}

func (r *trustedDeviceRow) device() *dbtype.TrustedDevice {
	return &dbtype.TrustedDevice{
		ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt,
	}
}

func (s *SessionStorageDriver) factorCodesTable() string {
	return pgx.Identifier{s.factorCodesTableName}.Sanitize()
}

func (s *SessionStorageDriver) trustedDevicesTable() string {
	return pgx.Identifier{s.trustedDevicesTableName}.Sanitize()
}

// InsertFactorCode consumes the earlier codes of c's pending sign-in that are live at
// now and inserts c, created at the database's time, unused and not consumed, whatever
// c carries, in one transaction: one code stands for a pending sign-in at a time.
func (s *SessionStorageDriver) InsertFactorCode(ctx context.Context, c *dbtype.FactorCode, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	err := s.Transact(ctx, func(ctx context.Context, tx pgx.Tx) error {
		consume := fmt.Sprintf(`UPDATE %s SET "ConsumedAt" = now() WHERE "PendingId" = $1 AND "ConsumedAt" IS NULL AND "ExpiresAt" > $2`, s.factorCodesTable())
		if _, err := tx.Exec(ctx, consume, c.PendingID, now); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}
		insert := fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1, $2, $3, $4, 0, now(), $5, NULL)`, s.factorCodesTable(), factorCodeColumns)
		if _, err := tx.Exec(ctx, insert, c.ID, c.PendingID, c.Email, c.CodeHash, c.ExpiresAt); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "SessionStorageDriver.Transact()")
	}

	return nil
}

// FactorCodeByPending returns the newest code of pendingID that is live at now: not
// consumed and not expired. None is NotFound.
func (s *SessionStorageDriver) FactorCodeByPending(ctx context.Context, pendingID ccc.UUID, now time.Time) (*dbtype.FactorCode, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "PendingId" = $1 AND "ConsumedAt" IS NULL AND "ExpiresAt" > $2 ORDER BY "CreatedAt" DESC, "Id" DESC LIMIT 1`, factorCodeColumns, s.factorCodesTable())
	var rows []*factorCodeRow
	if err := pgxscan.Select(ctx, s.conn, &rows, query, pendingID, now); err != nil {
		return nil, errors.Wrap(err, "pgxscan.Select()")
	}
	if len(rows) == 0 {
		return nil, httpio.NewNotFoundMessage("no live factor code")
	}

	return rows[0].code(), nil
}

// RecordFactorCodeAttempt counts a wrong code against the code id, when it is live at
// now, and returns the count. A code that is not live is NotFound.
func (s *SessionStorageDriver) RecordFactorCodeAttempt(ctx context.Context, id ccc.UUID, now time.Time) (int, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`UPDATE %s SET "Attempts" = "Attempts" + 1 WHERE "Id" = $1 AND "ConsumedAt" IS NULL AND "ExpiresAt" > $2 RETURNING "Attempts"`, s.factorCodesTable())
	var attempts int
	if err := s.conn.QueryRow(ctx, query, id, now).Scan(&attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, httpio.NewNotFoundMessage("no live factor code")
		}

		return 0, errors.Wrap(err, "Queryer.QueryRow().Scan()")
	}

	return attempts, nil
}

// ConsumeFactorCode marks the code id consumed, at the database's time, when it is live
// at now. A code that is not live is NotFound: the update is conditional, so a code is
// consumed once.
func (s *SessionStorageDriver) ConsumeFactorCode(ctx context.Context, id ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`UPDATE %s SET "ConsumedAt" = now() WHERE "Id" = $1 AND "ConsumedAt" IS NULL AND "ExpiresAt" > $2`, s.factorCodesTable())
	tag, err := s.conn.Exec(ctx, query, id, now)
	if err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}
	if tag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessage("no live factor code")
	}

	return nil
}

// FactorCodeState reads the code id whatever its state, for tests: NotFound when there
// is none.
func (s *SessionStorageDriver) FactorCodeState(ctx context.Context, id ccc.UUID) (*dbtype.FactorCode, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var rows []*factorCodeRow
	if err := pgxscan.Select(ctx, s.conn, &rows, fmt.Sprintf(`SELECT %s FROM %s WHERE "Id" = $1`, factorCodeColumns, s.factorCodesTable()), id); err != nil {
		return nil, errors.Wrap(err, "pgxscan.Select()")
	}
	if len(rows) == 0 {
		return nil, httpio.NewNotFoundMessage("no factor code")
	}

	return rows[0].code(), nil
}

// InsertTrustedDevice inserts d, created at the database's time, unused and not
// revoked, whatever d carries.
func (s *SessionStorageDriver) InsertTrustedDevice(ctx context.Context, d *dbtype.TrustedDevice) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1, $2, $3, now(), $4, NULL, NULL)`, s.trustedDevicesTable(), trustedDeviceColumns)
	if _, err := s.conn.Exec(ctx, query, d.ID, d.UserID, d.TokenHash, d.ExpiresAt); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}

// queryTrustedDevices runs query and renders its rows.
func (s *SessionStorageDriver) queryTrustedDevices(ctx context.Context, query string, args ...any) ([]*dbtype.TrustedDevice, error) {
	var rows []*trustedDeviceRow
	if err := pgxscan.Select(ctx, s.conn, &rows, query, args...); err != nil {
		return nil, errors.Wrap(err, "pgxscan.Select()")
	}
	devices := make([]*dbtype.TrustedDevice, len(rows))
	for i, r := range rows {
		devices[i] = r.device()
	}

	return devices, nil
}

// TrustedDeviceByToken returns the device holding tokenHash that is live at now: not
// revoked and not expired. Any other is NotFound.
func (s *SessionStorageDriver) TrustedDeviceByToken(ctx context.Context, tokenHash []byte, now time.Time) (*dbtype.TrustedDevice, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "TokenHash" = $1 AND "RevokedAt" IS NULL AND "ExpiresAt" > $2`, trustedDeviceColumns, s.trustedDevicesTable())
	devices, err := s.queryTrustedDevices(ctx, query, tokenHash, now)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, httpio.NewNotFoundMessage("no live trusted device")
	}

	return devices[0], nil
}

// TouchTrustedDevice moves the LastUsedAt of the device id to the database's time, when
// it is live at now; a device that is not live is left as it is.
func (s *SessionStorageDriver) TouchTrustedDevice(ctx context.Context, id ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`UPDATE %s SET "LastUsedAt" = now() WHERE "Id" = $1 AND "RevokedAt" IS NULL AND "ExpiresAt" > $2`, s.trustedDevicesTable())
	if _, err := s.conn.Exec(ctx, query, id, now); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}

// RevokeTrustedDevice revokes the device holding tokenHash, at the database's time,
// when it is live at now. A device that is not live is NotFound.
func (s *SessionStorageDriver) RevokeTrustedDevice(ctx context.Context, tokenHash []byte, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`UPDATE %s SET "RevokedAt" = now() WHERE "TokenHash" = $1 AND "RevokedAt" IS NULL AND "ExpiresAt" > $2`, s.trustedDevicesTable())
	tag, err := s.conn.Exec(ctx, query, tokenHash, now)
	if err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}
	if tag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessage("no live trusted device")
	}

	return nil
}

// RevokeTrustedDevices revokes every device of userID that is not revoked yet, at the
// database's time.
func (s *SessionStorageDriver) RevokeTrustedDevices(ctx context.Context, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`UPDATE %s SET "RevokedAt" = now() WHERE "UserId" = $1 AND "RevokedAt" IS NULL`, s.trustedDevicesTable())
	if _, err := s.conn.Exec(ctx, query, userID); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}

// TrustedDeviceState reads the device holding tokenHash whatever its state, for tests:
// NotFound when there is none.
func (s *SessionStorageDriver) TrustedDeviceState(ctx context.Context, tokenHash []byte) (*dbtype.TrustedDevice, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	devices, err := s.queryTrustedDevices(ctx, fmt.Sprintf(`SELECT %s FROM %s WHERE "TokenHash" = $1`, trustedDeviceColumns, s.trustedDevicesTable()), tokenHash)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, httpio.NewNotFoundMessage("no trusted device")
	}

	return devices[0], nil
}
