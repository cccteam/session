package postgres

import (
	"testing"

	"github.com/cccteam/session/internal/dbtype"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSessionStorageDriver_SignInConflict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want dbtype.SignInConflict
	}{
		{
			name: "a deadlock the database broke",
			err:  &pgconn.PgError{Code: pgerrcode.DeadlockDetected},
			want: dbtype.LockConflict,
		},
		{
			name: "a serialization failure",
			err:  &pgconn.PgError{Code: pgerrcode.SerializationFailure},
			want: dbtype.LockConflict,
		},
		{
			name: "a wrapped deadlock",
			err:  errors.Wrap(&pgconn.PgError{Code: pgerrcode.DeadlockDetected}, "pgx.Tx.Commit()"),
			want: dbtype.LockConflict,
		},
		{
			name: "the username index refusing a provisioned user's name",
			err:  &pgconn.PgError{Code: pgerrcode.UniqueViolation, ConstraintName: "SessionUsers_NormalizedUsername_idx"},
			want: dbtype.UsernameConflict,
		},
		{
			name: "the identities table refusing a link",
			err:  &pgconn.PgError{Code: pgerrcode.UniqueViolation, TableName: "SessionIdentities"},
			want: dbtype.IdentityConflict,
		},
		{
			name: "a unique violation elsewhere",
			err:  &pgconn.PgError{Code: pgerrcode.UniqueViolation, TableName: "Sessions"},
			want: dbtype.NoSignInConflict,
		},
		{
			name: "a lock timeout",
			err:  &pgconn.PgError{Code: pgerrcode.LockNotAvailable},
			want: dbtype.NoSignInConflict,
		},
		{
			name: "an error that is not PostgreSQL's",
			err:  errors.New("context canceled"),
			want: dbtype.NoSignInConflict,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &SessionStorageDriver{}
			if err := s.SetUserTableName("SessionUsers"); err != nil {
				t.Fatalf("SetUserTableName() error = %v", err)
			}
			if err := s.SetIdentitiesTableName("SessionIdentities"); err != nil {
				t.Fatalf("SetIdentitiesTableName() error = %v", err)
			}
			if got := s.SignInConflict(tt.err); got != tt.want {
				t.Errorf("SignInConflict() = %v, want %v", got, tt.want)
			}
		})
	}
}
