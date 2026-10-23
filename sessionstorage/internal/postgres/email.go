package postgres

import (
	"context"
	"fmt"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// The user's email address, in two states (see the auth set's SessionUserEmail
// migration). The address is matched without regard to case through the normalized
// column, which the database derives; on a store whose usernames are the addresses
// the database derives the address itself from the username, so the driver writes the
// username where it would write the address and never writes Email.

// errUsernameIsEmail is the refusal of a rename, or of an address entered by hand, on a
// store whose usernames are the addresses: both change through a verified link.
func errUsernameIsEmail() error {
	return httpio.NewConflictMessage("the username is the user's email address: it changes when the person verifies a new address, not by a rename")
}

// errEmailTaken is the refusal of an address another user holds, verified or not.
func errEmailTaken(email string) error {
	return httpio.NewConflictMessagef("the email address %q is already in use", email)
}

// UserByEmail returns the user holding the address, verified or not, matched without
// regard to case, or NotFound.
func (s *SessionStorageDriver) UserByEmail(ctx context.Context, email string) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "NormalizedEmail" = casefold(normalize($1))`, s.userSelectColumns(), s.userTable())

	user := &dbtype.SessionUser{}
	if err := pgxscan.Get(ctx, s.conn, user, query, email); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("no user holds the email address %q", email)
		}

		return nil, errors.Wrap(err, "pgxscan.Get()")
	}

	return user, nil
}

// SetUserEmail puts an address on the user by hand, unverified, or takes it off (nil):
// an administrator's entry for an invitation or a migration, which reserves the
// address. An address another user holds is a Conflict. On a store whose usernames
// are the addresses the entry is refused: the address is the username.
func (s *SessionStorageDriver) SetUserEmail(ctx context.Context, userID ccc.UUID, email *string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.usernameIsEmail {
		return errUsernameIsEmail()
	}
	query := fmt.Sprintf(`UPDATE %s SET "Email" = $2, "EmailVerifiedAt" = NULL WHERE "Id" = $1`, s.userTable())
	tag, err := s.conn.Exec(ctx, query, userID, email)
	if err != nil {
		if s.isEmailConflict(err) {
			return errEmailTaken(*email)
		}

		return errors.Wrap(err, "Queryer.Exec()")
	}
	if tag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
	}

	return nil
}

// VerifyUserEmail writes the address the person has just proven they read, verified
// at the transaction's time, replacing whatever the user held. On a store whose
// usernames are the addresses it is written as the username, which renames the user
// and its live sessions as SetUserUsername does. An address another user holds,
// verified or not, is a Conflict.
func (s *SessionStorageDriver) VerifyUserEmail(ctx context.Context, userID ccc.UUID, email string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.usernameIsEmail {
		err := s.renameUser(ctx, userID, email, `, "EmailVerifiedAt" = now()`)
		if httpio.HasConflict(err) {
			return errEmailTaken(email)
		}

		return err
	}

	query := fmt.Sprintf(`UPDATE %s SET "Email" = $2, "EmailVerifiedAt" = now() WHERE "Id" = $1`, s.userTable())
	tag, err := s.conn.Exec(ctx, query, userID, email)
	if err != nil {
		if s.isEmailConflict(err) {
			return errEmailTaken(email)
		}

		return errors.Wrap(err, "Queryer.Exec()")
	}
	if tag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
	}

	return nil
}

// ClaimVerifiedEmail is ClaimVerifiedEmailIn in a transaction of its own.
func (s *SessionStorageDriver) ClaimVerifiedEmail(ctx context.Context, userID ccc.UUID, email string) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var claimed bool
	err := s.Transact(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		claimed, err = s.ClaimVerifiedEmailIn(ctx, tx, userID, email)

		return err
	})
	if err != nil {
		return false, err
	}

	return claimed, nil
}

// ClaimVerifiedEmailIn writes email on the user as verified, at the transaction's
// time, when the user holds no verified address yet and no other user holds email: a
// Google sign-in's verified address, or the address an accepted invitation was sent
// to. It reports whether it wrote. On a store whose usernames are the addresses only
// the verified time is written, and only when the address is the user's username. A
// user that already holds a verified address keeps it.
func (s *SessionStorageDriver) ClaimVerifiedEmailIn(ctx context.Context, tx pgx.Tx, userID ccc.UUID, email string) (bool, error) {
	var query string
	if s.usernameIsEmail {
		query = fmt.Sprintf(`
			UPDATE %s SET "EmailVerifiedAt" = now()
			WHERE "Id" = $1 AND "EmailVerifiedAt" IS NULL AND "NormalizedEmail" = casefold(normalize($2))`, s.userTable())
	} else {
		query = fmt.Sprintf(`
			UPDATE %s u SET "Email" = $2, "EmailVerifiedAt" = now()
			WHERE u."Id" = $1 AND u."EmailVerifiedAt" IS NULL
			  AND NOT EXISTS (SELECT 1 FROM %s other WHERE other."NormalizedEmail" = casefold(normalize($2)) AND other."Id" <> $1)`, s.userTable(), s.userTable())
	}
	tag, err := tx.Exec(ctx, query, userID, email)
	if err != nil {
		return false, errors.Wrap(err, "pgx.Tx.Exec()")
	}

	return tag.RowsAffected() > 0, nil
}

// UserByEmailIn reads the user holding email inside tx, verified or not, matched
// without regard to case, or nil when there is none.
func (s *SessionStorageDriver) UserByEmailIn(ctx context.Context, tx pgx.Tx, email string) (*dbtype.User, error) {
	query := fmt.Sprintf(`SELECT "Id", "Username", "PasswordHash" IS NOT NULL, "Disabled" FROM %s WHERE "NormalizedEmail" = casefold(normalize($1))`, s.userTable())

	var u dbtype.User
	if err := tx.QueryRow(ctx, query, email).Scan(&u.ID, &u.Username, &u.HasPassword, &u.Disabled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}

	return &u, nil
}
