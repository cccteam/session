package spanner

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/go-playground/errors/v5"
	"google.golang.org/grpc/codes"
)

// attemptsColumns are the sign-in attempts table's columns.
var attemptsColumns = []string{"Name", "Failures", "WindowEndsAt", "LockedUntil", updatedAtColumn}

// updatedAtColumn is the column the commit time is written to.
const updatedAtColumn = "UpdatedAt"

// attemptsRow is a sign-in attempts record as the table holds it.
type attemptsRow struct {
	Name         string           `spanner:"Name"`
	Failures     int64            `spanner:"Failures"`
	WindowEndsAt time.Time        `spanner:"WindowEndsAt"`
	LockedUntil  spanner.NullTime `spanner:"LockedUntil"`
	UpdatedAt    time.Time        `spanner:"UpdatedAt"`
}

func (r *attemptsRow) record() *dbtype.SignInAttempts {
	rec := &dbtype.SignInAttempts{Name: r.Name, Failures: r.Failures, WindowEndsAt: r.WindowEndsAt, UpdatedAt: r.UpdatedAt}
	if r.LockedUntil.Valid {
		lockedUntil := r.LockedUntil.Time
		rec.LockedUntil = &lockedUntil
	}

	return rec
}

// readAttempts reads name's record through read; found is false when there is none.
func readAttempts(
	ctx context.Context, read func(ctx context.Context, table string, key spanner.Key, columns []string) (*spanner.Row, error), table, name string,
) (record *dbtype.SignInAttempts, found bool, err error) {
	row, err := read(ctx, table, spanner.Key{name}, attemptsColumns)
	if err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return nil, false, nil
		}

		return nil, false, errors.Wrap(err, "ReadRow()")
	}
	var r attemptsRow
	if err := row.ToStruct(&r); err != nil {
		return nil, false, errors.Wrap(err, "spanner.Row.ToStruct()")
	}

	return r.record(), true, nil
}

// SignInAttempts returns the sign-in attempts record of name, or NotFound when there
// is none.
func (s *SessionStorageDriver) SignInAttempts(ctx context.Context, name string) (*dbtype.SignInAttempts, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	record, found, err := readAttempts(ctx, s.spanner.Single().ReadRow, s.attemptsTableName, name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, httpio.NewNotFoundMessage("no sign-in attempts recorded")
	}

	return record, nil
}

// RecordSignInFailure records a failed attempt on name at now under limit and returns
// the record as written, with UpdatedAt the commit time. The record is read and
// written in one read-write transaction, which Spanner retries when another failure
// of the same name commits first, so concurrent failures each count: the rule
// (dbtype.SignInAttempts.Failed) is applied to what the transaction's read shows.
func (s *SessionStorageDriver) RecordSignInFailure(ctx context.Context, name string, now time.Time, limit dbtype.SignInAttemptLimit) (*dbtype.SignInAttempts, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var record *dbtype.SignInAttempts
	commit, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		current, _, err := readAttempts(ctx, txn.ReadRow, s.attemptsTableName, name)
		if err != nil {
			return err
		}
		next := current.Failed(name, now, limit)
		row := map[string]any{
			"Name": next.Name, "Failures": next.Failures, "WindowEndsAt": next.WindowEndsAt, "LockedUntil": spanner.NullTime{}, updatedAtColumn: spanner.CommitTimestamp,
		}
		if next.LockedUntil != nil {
			row["LockedUntil"] = spanner.NullTime{Time: *next.LockedUntil, Valid: true}
		}
		if err := txn.BufferWrite([]*spanner.Mutation{spanner.InsertOrUpdateMap(s.attemptsTableName, row)}); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.BufferWrite()")
		}
		record = next

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}
	record.UpdatedAt = commit

	return record, nil
}

// ClearSignInAttempts deletes the sign-in attempts record of name, if there is one.
func (s *SessionStorageDriver) ClearSignInAttempts(ctx context.Context, name string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{spanner.Delete(s.attemptsTableName, spanner.Key{name})}); err != nil {
		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}
