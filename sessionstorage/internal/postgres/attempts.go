package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// attemptsColumns are the sign-in attempts table's columns, in attemptsRow's order.
const attemptsColumns = `"Name", "Failures", "WindowEndsAt", "LockedUntil", "UpdatedAt"`

// attemptsRow is a sign-in attempts record as the table holds it.
type attemptsRow struct {
	Name         string     `db:"Name"`
	Failures     int64      `db:"Failures"`
	WindowEndsAt time.Time  `db:"WindowEndsAt"`
	LockedUntil  *time.Time `db:"LockedUntil"`
	UpdatedAt    time.Time  `db:"UpdatedAt"`
}

func (r *attemptsRow) record() *dbtype.SignInAttempts {
	return &dbtype.SignInAttempts{Name: r.Name, Failures: r.Failures, WindowEndsAt: r.WindowEndsAt, LockedUntil: r.LockedUntil, UpdatedAt: r.UpdatedAt}
}

func (s *SessionStorageDriver) attemptsTable() string {
	return pgx.Identifier{s.attemptsTableName}.Sanitize()
}

// SignInAttempts returns the sign-in attempts record of name, or NotFound when there
// is none.
func (s *SessionStorageDriver) SignInAttempts(ctx context.Context, name string) (*dbtype.SignInAttempts, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "Name" = $1 AND "Failures" > 0`, attemptsColumns, s.attemptsTable())

	var row attemptsRow
	if err := pgxscan.Get(ctx, s.conn, &row, query, name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessage("no sign-in attempts recorded")
		}

		return nil, errors.Wrap(err, "pgxscan.Get()")
	}

	return row.record(), nil
}

// RecordSignInFailure records a failed attempt on name at now under limit and returns
// the record as written, with UpdatedAt the database's time. The record is read and
// written in one transaction under a row lock, so concurrent failures each count: a
// row with no failures is inserted first and locked, and the rule
// (dbtype.SignInAttempts.Failed) is applied to what the lock then shows.
func (s *SessionStorageDriver) RecordSignInFailure(ctx context.Context, name string, now time.Time, limit dbtype.SignInAttemptLimit) (*dbtype.SignInAttempts, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var record *dbtype.SignInAttempts
	err := s.Transact(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// The placeholder row serializes the first failures of one name: a concurrent
		// insert of the same name waits for this transaction, then finds the row.
		placeholder := fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1, 0, now(), NULL, now()) ON CONFLICT ("Name") DO NOTHING`, s.attemptsTable(), attemptsColumns)
		if _, err := tx.Exec(ctx, placeholder, name); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}

		var row attemptsRow
		if err := pgxscan.Get(ctx, tx, &row, fmt.Sprintf(`SELECT %s FROM %s WHERE "Name" = $1 FOR UPDATE`, attemptsColumns, s.attemptsTable()), name); err != nil {
			return errors.Wrap(err, "pgxscan.Get()")
		}
		var current *dbtype.SignInAttempts
		if row.Failures > 0 {
			current = row.record()
		}
		next := current.Failed(name, now, limit)

		update := fmt.Sprintf(`UPDATE %s SET "Failures" = $2, "WindowEndsAt" = $3, "LockedUntil" = $4, "UpdatedAt" = now() WHERE "Name" = $1 RETURNING "UpdatedAt"`, s.attemptsTable())
		if err := tx.QueryRow(ctx, update, name, next.Failures, next.WindowEndsAt, next.LockedUntil).Scan(&next.UpdatedAt); err != nil {
			return errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
		}
		record = next

		return nil
	})
	if err != nil {
		return nil, err
	}

	return record, nil
}

// ClearSignInAttempts deletes the sign-in attempts record of name, if there is one.
func (s *SessionStorageDriver) ClearSignInAttempts(ctx context.Context, name string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if _, err := s.conn.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE "Name" = $1`, s.attemptsTable()), name); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}
