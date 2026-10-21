package spanner

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/go-playground/errors/v5"
	"google.golang.org/api/iterator"
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

// rowReader reads the rows of a key set from a table, as spanner.ReadOnlyTransaction.Read
// and spanner.ReadWriteTransaction.Read do: the iterator answers iterator.Done for a key
// with no row, and any failure of the read itself is the iterator's error.
type rowReader func(ctx context.Context, table string, keys spanner.KeySet, columns []string) *spanner.RowIterator

// readAttempts reads name's record from table through read; found is false when there is
// none. The read tells a missing row from a failed read: a key with no row ends the
// iterator (iterator.Done), while any other error, a missing table among them, is
// returned naming the table. A ReadRow answers NotFound for both a missing row and a
// missing table, and a read that failed has ended a read-write transaction, so taking
// that NotFound for "no record yet" let the write that followed fail on a closed
// transaction instead of saying what was wrong.
func readAttempts(ctx context.Context, read rowReader, table, name string) (record *dbtype.SignInAttempts, found bool, err error) {
	iter := read(ctx, table, spanner.Key{name}, attemptsColumns)
	defer iter.Stop()

	row, err := iter.Next()
	if err != nil {
		if errors.Is(err, iterator.Done) {
			return nil, false, nil
		}

		return nil, false, errors.Wrapf(err, "reading %s", table)
	}
	var r attemptsRow
	if err := row.ToStruct(&r); err != nil {
		return nil, false, errors.Wrap(err, "spanner.Row.ToStruct()")
	}

	return r.record(), true, nil
}

// SignInAttempts returns the sign-in attempts record of name, or NotFound when there
// is none. A read that fails, as it does when the table is missing, is returned as its
// own error, which names the table.
func (s *SessionStorageDriver) SignInAttempts(ctx context.Context, name string) (*dbtype.SignInAttempts, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	record, found, err := readAttempts(ctx, s.spanner.Single().Read, s.attemptsTableName, name)
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
// (dbtype.SignInAttempts.Failed) is applied to what the transaction's read shows. A
// read that fails, as it does when the table is missing, ends the transaction with the
// read's own error, which names the table; nothing is written.
func (s *SessionStorageDriver) RecordSignInFailure(ctx context.Context, name string, now time.Time, limit dbtype.SignInAttemptLimit) (*dbtype.SignInAttempts, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var record *dbtype.SignInAttempts
	commit, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		current, _, err := readAttempts(ctx, txn.Read, s.attemptsTableName, name)
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
