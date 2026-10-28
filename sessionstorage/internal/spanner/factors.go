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

// factorCodeColumns are the factor codes table's columns.
const factorCodeColumns = `Id, PendingId, Email, CodeHash, Attempts, CreatedAt, ExpiresAt, ConsumedAt`

// factorCodeRow is a factor code as the table holds it.
type factorCodeRow struct {
	ID         string           `spanner:"Id"`
	PendingID  string           `spanner:"PendingId"`
	Email      string           `spanner:"Email"`
	CodeHash   []byte           `spanner:"CodeHash"`
	Attempts   int64            `spanner:"Attempts"`
	CreatedAt  time.Time        `spanner:"CreatedAt"`
	ExpiresAt  time.Time        `spanner:"ExpiresAt"`
	ConsumedAt spanner.NullTime `spanner:"ConsumedAt"`
}

// newFactorCodeRow renders c as the table holds it: created at the commit time, unused
// and not consumed, whatever c carries.
func newFactorCodeRow(c *dbtype.FactorCode) *factorCodeRow {
	return &factorCodeRow{
		ID: c.ID.String(), PendingID: c.PendingID.String(), Email: c.Email, CodeHash: c.CodeHash, Attempts: 0,
		CreatedAt: spanner.CommitTimestamp, ExpiresAt: c.ExpiresAt,
	}
}

func (r *factorCodeRow) code() (*dbtype.FactorCode, error) {
	id, err := ccc.UUIDFromString(r.ID)
	if err != nil {
		return nil, errors.Wrap(err, "ccc.UUIDFromString()")
	}
	pendingID, err := ccc.UUIDFromString(r.PendingID)
	if err != nil {
		return nil, errors.Wrap(err, "ccc.UUIDFromString()")
	}
	c := &dbtype.FactorCode{
		ID: id, PendingID: pendingID, Email: r.Email, CodeHash: r.CodeHash, Attempts: int(r.Attempts), CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
	}
	if r.ConsumedAt.Valid {
		consumedAt := r.ConsumedAt.Time
		c.ConsumedAt = &consumedAt
	}

	return c, nil
}

// trustedDeviceColumns are the trusted devices table's columns.
const trustedDeviceColumns = `Id, UserId, TokenHash, CreatedAt, ExpiresAt, LastUsedAt, RevokedAt`

// trustedDeviceRow is a trusted device as the table holds it.
type trustedDeviceRow struct {
	ID         string           `spanner:"Id"`
	UserID     string           `spanner:"UserId"`
	TokenHash  []byte           `spanner:"TokenHash"`
	CreatedAt  time.Time        `spanner:"CreatedAt"`
	ExpiresAt  time.Time        `spanner:"ExpiresAt"`
	LastUsedAt spanner.NullTime `spanner:"LastUsedAt"`
	RevokedAt  spanner.NullTime `spanner:"RevokedAt"`
}

// newTrustedDeviceRow renders d as the table holds it: created at the commit time,
// unused and not revoked, whatever d carries.
func newTrustedDeviceRow(d *dbtype.TrustedDevice) *trustedDeviceRow {
	return &trustedDeviceRow{ID: d.ID.String(), UserID: d.UserID.String(), TokenHash: d.TokenHash, CreatedAt: spanner.CommitTimestamp, ExpiresAt: d.ExpiresAt}
}

func (r *trustedDeviceRow) device() (*dbtype.TrustedDevice, error) {
	id, err := ccc.UUIDFromString(r.ID)
	if err != nil {
		return nil, errors.Wrap(err, "ccc.UUIDFromString()")
	}
	userID, err := ccc.UUIDFromString(r.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "ccc.UUIDFromString()")
	}
	d := &dbtype.TrustedDevice{ID: id, UserID: userID, TokenHash: r.TokenHash, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}
	if r.LastUsedAt.Valid {
		lastUsedAt := r.LastUsedAt.Time
		d.LastUsedAt = &lastUsedAt
	}
	if r.RevokedAt.Valid {
		revokedAt := r.RevokedAt.Time
		d.RevokedAt = &revokedAt
	}

	return d, nil
}

// errFactorCodeNotLive and errTrustedDeviceNotLive are a transaction's signal that the
// conditional update changed no row.
var (
	errFactorCodeNotLive    = errors.New("no live factor code")
	errTrustedDeviceNotLive = errors.New("no live trusted device")
)

// InsertFactorCode consumes the earlier codes of c's pending sign-in that are live at
// now and inserts c, in one transaction: one code stands for a pending sign-in at a
// time.
func (s *SessionStorageDriver) InsertFactorCode(ctx context.Context, c *dbtype.FactorCode, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	m, err := spanner.InsertStruct(s.factorCodesTableName, newFactorCodeRow(c))
	if err != nil {
		return errors.Wrap(err, "spanner.InsertStruct()")
	}
	_, err = s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET ConsumedAt = PENDING_COMMIT_TIMESTAMP() WHERE PendingId = @pendingId AND ConsumedAt IS NULL AND ExpiresAt > @now`, s.factorCodesTableName))
		stmt.Params["pendingId"] = c.PendingID.String()
		stmt.Params["now"] = now
		if _, err := txn.Update(ctx, stmt); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}
		if err := txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.BufferWrite()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// queryFactorCodes runs stmt and renders its rows.
func (s *SessionStorageDriver) queryFactorCodes(ctx context.Context, stmt spanner.Statement) ([]*dbtype.FactorCode, error) {
	iter := s.spanner.Single().Query(ctx, stmt)
	defer iter.Stop()

	var codes []*dbtype.FactorCode
	for {
		row, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return codes, nil
		}
		if err != nil {
			return nil, errors.Wrap(err, "spanner.RowIterator.Next()")
		}
		var r factorCodeRow
		if err := row.ToStruct(&r); err != nil {
			return nil, errors.Wrap(err, "spanner.Row.ToStruct()")
		}
		c, err := r.code()
		if err != nil {
			return nil, err
		}
		codes = append(codes, c)
	}
}

// FactorCodeByPending returns the newest code of pendingID that is live at now: not
// consumed and not expired. None is NotFound.
func (s *SessionStorageDriver) FactorCodeByPending(ctx context.Context, pendingID ccc.UUID, now time.Time) (*dbtype.FactorCode, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(
		`SELECT %s FROM %s WHERE PendingId = @pendingId AND ConsumedAt IS NULL AND ExpiresAt > @now ORDER BY CreatedAt DESC, Id DESC LIMIT 1`,
		factorCodeColumns, s.factorCodesTableName,
	))
	stmt.Params["pendingId"] = pendingID.String()
	stmt.Params["now"] = now

	codes, err := s.queryFactorCodes(ctx, stmt)
	if err != nil {
		return nil, err
	}
	if len(codes) == 0 {
		return nil, httpio.NewNotFoundMessage("no live factor code")
	}

	return codes[0], nil
}

// RecordFactorCodeAttempt counts a wrong code against the code id, when it is live at
// now, and returns the count, in one transaction. A code that is not live is NotFound.
func (s *SessionStorageDriver) RecordFactorCodeAttempt(ctx context.Context, id ccc.UUID, now time.Time) (int, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var attempts int64
	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		read := spanner.NewStatement(fmt.Sprintf(`SELECT Attempts FROM %s WHERE Id = @id AND ConsumedAt IS NULL AND ExpiresAt > @now`, s.factorCodesTableName))
		read.Params["id"] = id.String()
		read.Params["now"] = now
		var current int64
		found := false
		if err := txn.Query(ctx, read).Do(func(r *spanner.Row) error {
			found = true

			return r.Column(0, &current)
		}); err != nil {
			return errors.Wrap(err, "spanner.RowIterator.Do()")
		}
		if !found {
			return errFactorCodeNotLive
		}
		attempts = current + 1
		if err := txn.BufferWrite([]*spanner.Mutation{spanner.UpdateMap(s.factorCodesTableName, map[string]any{idColumn: id.String(), "Attempts": attempts})}); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.BufferWrite()")
		}

		return nil
	})
	if errors.Is(err, errFactorCodeNotLive) {
		return 0, httpio.NewNotFoundMessage("no live factor code")
	}
	if err != nil {
		return 0, errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return int(attempts), nil
}

// ConsumeFactorCode marks the code id consumed, at the commit time, when it is live at
// now. A code that is not live is NotFound: the update is conditional, so a code is
// consumed once.
func (s *SessionStorageDriver) ConsumeFactorCode(ctx context.Context, id ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET ConsumedAt = PENDING_COMMIT_TIMESTAMP() WHERE Id = @id AND ConsumedAt IS NULL AND ExpiresAt > @now`, s.factorCodesTableName))
	stmt.Params["id"] = id.String()
	stmt.Params["now"] = now
	if err := s.conditionalUpdate(ctx, stmt, errFactorCodeNotLive); err != nil {
		if errors.Is(err, errFactorCodeNotLive) {
			return httpio.NewNotFoundMessage("no live factor code")
		}

		return err
	}

	return nil
}

// conditionalUpdate runs stmt in a transaction of its own and answers notLive when it
// changed no row.
func (s *SessionStorageDriver) conditionalUpdate(ctx context.Context, stmt spanner.Statement, notLive error) error {
	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		n, err := txn.Update(ctx, stmt)
		if err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}
		if n == 0 {
			return notLive
		}

		return nil
	})
	if errors.Is(err, notLive) {
		return notLive
	}
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// FactorCodeState reads the code id whatever its state, for tests: NotFound when there
// is none.
func (s *SessionStorageDriver) FactorCodeState(ctx context.Context, id ccc.UUID) (*dbtype.FactorCode, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE Id = @id`, factorCodeColumns, s.factorCodesTableName))
	stmt.Params["id"] = id.String()
	codes, err := s.queryFactorCodes(ctx, stmt)
	if err != nil {
		return nil, err
	}
	if len(codes) == 0 {
		return nil, httpio.NewNotFoundMessage("no factor code")
	}

	return codes[0], nil
}

// InsertTrustedDevice inserts d.
func (s *SessionStorageDriver) InsertTrustedDevice(ctx context.Context, d *dbtype.TrustedDevice) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	m, err := spanner.InsertStruct(s.trustedDevicesTableName, newTrustedDeviceRow(d))
	if err != nil {
		return errors.Wrap(err, "spanner.InsertStruct()")
	}
	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{m}); err != nil {
		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// queryTrustedDevices runs stmt and renders its rows.
func (s *SessionStorageDriver) queryTrustedDevices(ctx context.Context, stmt spanner.Statement) ([]*dbtype.TrustedDevice, error) {
	iter := s.spanner.Single().Query(ctx, stmt)
	defer iter.Stop()

	var devices []*dbtype.TrustedDevice
	for {
		row, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return devices, nil
		}
		if err != nil {
			return nil, errors.Wrap(err, "spanner.RowIterator.Next()")
		}
		var r trustedDeviceRow
		if err := row.ToStruct(&r); err != nil {
			return nil, errors.Wrap(err, "spanner.Row.ToStruct()")
		}
		d, err := r.device()
		if err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
}

// TrustedDeviceByToken returns the device holding tokenHash that is live at now: not
// revoked and not expired. Any other is NotFound.
func (s *SessionStorageDriver) TrustedDeviceByToken(ctx context.Context, tokenHash []byte, now time.Time) (*dbtype.TrustedDevice, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE TokenHash = @tokenHash AND RevokedAt IS NULL AND ExpiresAt > @now`, trustedDeviceColumns, s.trustedDevicesTableName))
	stmt.Params["tokenHash"] = tokenHash
	stmt.Params["now"] = now

	devices, err := s.queryTrustedDevices(ctx, stmt)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, httpio.NewNotFoundMessage("no live trusted device")
	}

	return devices[0], nil
}

// TouchTrustedDevice moves the LastUsedAt of the device id to the commit time, when it
// is live at now; a device that is not live is left as it is.
func (s *SessionStorageDriver) TouchTrustedDevice(ctx context.Context, id ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET LastUsedAt = PENDING_COMMIT_TIMESTAMP() WHERE Id = @id AND RevokedAt IS NULL AND ExpiresAt > @now`, s.trustedDevicesTableName))
	stmt.Params["id"] = id.String()
	stmt.Params["now"] = now
	if err := s.conditionalUpdate(ctx, stmt, errTrustedDeviceNotLive); err != nil && !errors.Is(err, errTrustedDeviceNotLive) {
		return err
	}

	return nil
}

// RevokeTrustedDevice revokes the device holding tokenHash, at the commit time, when it
// is live at now. A device that is not live is NotFound.
func (s *SessionStorageDriver) RevokeTrustedDevice(ctx context.Context, tokenHash []byte, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET RevokedAt = PENDING_COMMIT_TIMESTAMP() WHERE TokenHash = @tokenHash AND RevokedAt IS NULL AND ExpiresAt > @now`, s.trustedDevicesTableName))
	stmt.Params["tokenHash"] = tokenHash
	stmt.Params["now"] = now
	if err := s.conditionalUpdate(ctx, stmt, errTrustedDeviceNotLive); err != nil {
		if errors.Is(err, errTrustedDeviceNotLive) {
			return httpio.NewNotFoundMessage("no live trusted device")
		}

		return err
	}

	return nil
}

// RevokeTrustedDevices revokes every device of userID that is not revoked yet, at the
// commit time.
func (s *SessionStorageDriver) RevokeTrustedDevices(ctx context.Context, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET RevokedAt = PENDING_COMMIT_TIMESTAMP() WHERE UserId = @userId AND RevokedAt IS NULL`, s.trustedDevicesTableName))
		stmt.Params["userId"] = userID.String()
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

// TrustedDeviceState reads the device holding tokenHash whatever its state, for tests:
// NotFound when there is none.
func (s *SessionStorageDriver) TrustedDeviceState(ctx context.Context, tokenHash []byte) (*dbtype.TrustedDevice, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE TokenHash = @tokenHash`, trustedDeviceColumns, s.trustedDevicesTableName))
	stmt.Params["tokenHash"] = tokenHash
	devices, err := s.queryTrustedDevices(ctx, stmt)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, httpio.NewNotFoundMessage("no trusted device")
	}

	return devices[0], nil
}
