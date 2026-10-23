package spanner

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/spxscan"
	"github.com/cccteam/spxscan/spxapi"
	"github.com/go-playground/errors/v5"
	"google.golang.org/grpc/codes"
)

// The user's email address, in two states (see the auth set's SessionUserEmail
// migration). The address is matched without regard to case through the normalized
// column, which the database derives; on a store whose usernames are the addresses
// the database derives the address itself from the username, so the driver writes the
// username where it would write the address and never writes Email.

// emailVerifiedAtColumn is the column that records when the address was verified.
const emailVerifiedAtColumn = "EmailVerifiedAt"

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

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE NormalizedEmail = NORMALIZE_AND_CASEFOLD(@email)`, s.userSelectColumns(), s.userTableName))
	stmt.Params["email"] = email

	user := &dbtype.SessionUser{}
	if err := spxscan.Get(ctx, s.spanner.Single(), user, stmt); err != nil {
		if errors.Is(err, spxapi.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("no user holds the email address %q", email)
		}

		return nil, errors.Wrap(err, "spxscan.Get()")
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
	row := map[string]any{idColumn: userID, "Email": spanner.NullString{}, emailVerifiedAtColumn: spanner.NullTime{}}
	if email != nil {
		row["Email"] = spanner.NullString{StringVal: *email, Valid: true}
	}
	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{spanner.UpdateMap(s.userTableName, row)}); err != nil {
		switch {
		case spanner.ErrCode(err) == codes.NotFound:
			return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
		case spanner.ErrCode(err) == codes.AlreadyExists && strings.Contains(err.Error(), s.emailIndex()):
			return errEmailTaken(*email)
		}

		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// VerifyUserEmail writes the address the person has just proven they read, verified
// at the commit time, replacing whatever the user held. On a store whose usernames
// are the addresses it is written as the username, which renames the user and its
// live sessions as SetUserUsername does. An address another user holds, verified or
// not, is a Conflict.
func (s *SessionStorageDriver) VerifyUserEmail(ctx context.Context, userID ccc.UUID, email string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.usernameIsEmail {
		err := s.renameUser(ctx, userID, email, map[string]any{emailVerifiedAtColumn: spanner.CommitTimestamp})
		if httpio.HasConflict(err) {
			return errEmailTaken(email)
		}

		return err
	}

	row := map[string]any{idColumn: userID, "Email": email, emailVerifiedAtColumn: spanner.CommitTimestamp}
	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{spanner.UpdateMap(s.userTableName, row)}); err != nil {
		switch {
		case spanner.ErrCode(err) == codes.NotFound:
			return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
		case spanner.ErrCode(err) == codes.AlreadyExists && strings.Contains(err.Error(), s.emailIndex()):
			return errEmailTaken(email)
		}

		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// ClaimVerifiedEmail is ClaimVerifiedEmailIn in a transaction of its own.
func (s *SessionStorageDriver) ClaimVerifiedEmail(ctx context.Context, userID ccc.UUID, email string) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var claimed bool
	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		var err error
		claimed, err = s.ClaimVerifiedEmailIn(ctx, txn, userID, email)

		return err
	})
	if err != nil {
		return false, errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return claimed, nil
}

// ClaimVerifiedEmailIn writes email on the user as verified, at the commit time, when
// the user holds no verified address yet and no other user holds email: a Google
// sign-in's verified address, or the address an accepted invitation was sent to. It
// reports whether it wrote. On a store whose usernames are the addresses only the
// verified time is written, and only when the address is the user's username. A user
// that already holds a verified address keeps it. The checks are reads in the
// transaction and the write a buffered mutation: the emulator refuses a DML update of
// a column a generated column derives from when the statement reads the table too,
// and the serializable transaction keeps read and write together.
func (s *SessionStorageDriver) ClaimVerifiedEmailIn(ctx context.Context, tx *spanner.ReadWriteTransaction, userID ccc.UUID, email string) (bool, error) {
	holder, err := s.UserByEmailIn(ctx, tx, email)
	if err != nil {
		return false, err
	}
	switch {
	case holder != nil && holder.ID != userID:
		return false, nil
	case s.usernameIsEmail && holder == nil:
		return false, nil
	}
	row, err := tx.ReadRow(ctx, s.userTableName, spanner.Key{userID.String()}, []string{emailVerifiedAtColumn})
	if err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return false, nil
		}

		return false, errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
	}
	var verifiedAt spanner.NullTime
	if err := row.Column(0, &verifiedAt); err != nil {
		return false, errors.Wrap(err, "spanner.Row.Column()")
	}
	if verifiedAt.Valid {
		return false, nil
	}
	update := map[string]any{idColumn: userID, emailVerifiedAtColumn: spanner.CommitTimestamp}
	if !s.usernameIsEmail {
		update["Email"] = email
	}
	if err := tx.BufferWrite([]*spanner.Mutation{spanner.UpdateMap(s.userTableName, update)}); err != nil {
		return false, errors.Wrap(err, "spanner.ReadWriteTransaction.BufferWrite()")
	}

	return true, nil
}

// UserByEmailIn reads the user holding email inside tx, verified or not, matched
// without regard to case, or nil when there is none.
func (s *SessionStorageDriver) UserByEmailIn(ctx context.Context, tx *spanner.ReadWriteTransaction, email string) (*dbtype.User, error) {
	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT Id, Username, PasswordHash, Disabled FROM %s WHERE NormalizedEmail = NORMALIZE_AND_CASEFOLD(@email)`, s.userTableName))
	stmt.Params["email"] = email

	var user *dbtype.User
	err := tx.Query(ctx, stmt).Do(func(row *spanner.Row) error {
		u, err := userOf(row)
		if err != nil {
			return err
		}
		user = u

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.RowIterator.Do()")
	}

	return user, nil
}
