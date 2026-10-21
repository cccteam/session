package e2e

import (
	"context"
	"strings"
	"testing"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	dbinitiator "github.com/cccteam/db-initiator"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
)

// backend is one storage driver the Auth scenarios run on, generic over the driver's
// transaction type as an application over that driver is. It prepares a database with
// the shipped migrations and the application's own tables, builds the Auth store over
// it, and reaches the application's rows the two ways an application does: inside a
// sign-in's transaction from its hooks, and outside one.
type backend[Tx any] struct {
	name     string
	newStore func(ctx context.Context, t *testing.T) (appDB, *sessionstorage.Auth[Tx])
	rows     appRows[Tx]
}

// appDB is the scenarios' own handle on the database, for what they check or arrange
// behind the library's back.
type appDB interface {
	// username reads a user's username.
	username(ctx context.Context, t *testing.T, userID ccc.UUID) string
	// attemptOutcome reads the outcome a resolver recorded for subject, "" when none.
	attemptOutcome(ctx context.Context, t *testing.T, subject string) string
	// disableUser disables a user.
	disableUser(ctx context.Context, t *testing.T, userID ccc.UUID)
	// hasUser reports whether a user exists under username, as stored.
	hasUser(ctx context.Context, t *testing.T, username string) bool
	// declareTenant writes tenant's declaration: the directories it admits its people
	// through, and whether through those only.
	declareTenant(ctx context.Context, t *testing.T, tenant string, directoryOnly bool, directories ...signin.Directory)
}

// appRows reads and writes the application's own tables in a sign-in's transaction, the
// way an application's hooks do.
type appRows[Tx any] struct {
	// addMember records userID as a member of partner.
	addMember func(ctx context.Context, tx Tx, userID ccc.UUID, partner string) error
	// partnerOf reads the partner userID is a member of.
	partnerOf func(ctx context.Context, tx Tx, userID ccc.UUID) (partner string, found bool, err error)
	// recordAttempt records the outcome of subject's sign-in attempt.
	recordAttempt func(ctx context.Context, tx Tx, subject, outcome string) error
	// tenantDeclaration reads tenant's declaration for the tenant policy, nil when the
	// tenant declares nothing.
	tenantDeclaration func(ctx context.Context, tx Tx, tenant accesstypes.Domain) (*signin.TenantDeclaration, error)
}

// renderDirectories renders directories as the TenantDeclarations row keeps them:
// method:connection, comma-separated.
func renderDirectories(directories []signin.Directory) string {
	parts := make([]string, 0, len(directories))
	for _, d := range directories {
		parts = append(parts, string(d.Method)+":"+d.Connection)
	}

	return strings.Join(parts, ",")
}

// parseDirectories reads renderDirectories' form back.
func parseDirectories(rendered string) []signin.Directory {
	if rendered == "" {
		return nil
	}
	var directories []signin.Directory
	for part := range strings.SplitSeq(rendered, ",") {
		method, connection, _ := strings.Cut(part, ":")
		directories = append(directories, signin.Directory{Method: sessioninfo.AuthMethod(method), Connection: connection})
	}

	return directories
}

// storeTables are the auth events and impersonation tables every Auth store in these
// scenarios has.
func storeTables(t *testing.T) (*sessionstorage.AuthEventsTable, *sessionstorage.ImpersonationTable) {
	t.Helper()

	events, err := sessionstorage.NewAuthEventsTable("SessionAuthEvents")
	if err != nil {
		t.Fatalf("sessionstorage.NewAuthEventsTable() error = %v", err)
	}
	impersonation, err := sessionstorage.NewImpersonationTable("SessionImpersonations")
	if err != nil {
		t.Fatalf("sessionstorage.NewImpersonationTable() error = %v", err)
	}

	return events, impersonation
}

var postgresBackend = backend[pgx.Tx]{
	name: "postgres",
	newStore: func(ctx context.Context, t *testing.T) (appDB, *sessionstorage.Auth[pgx.Tx]) {
		t.Helper()

		db := preparePostgres(ctx, t, postgresSessions, postgresImpersonation, postgresAuth, postgresAppTables)
		events, impersonation := storeTables(t)

		return postgresDB{db}, sessionstorage.NewPostgresAuth(db.Pool, sessionstorage.WithAuthEvents(events), sessionstorage.WithImpersonation(impersonation))
	},
	rows: appRows[pgx.Tx]{
		addMember: func(ctx context.Context, tx pgx.Tx, userID ccc.UUID, partner string) error {
			if _, err := tx.Exec(ctx, `INSERT INTO "PartnerMembers" ("UserId", "Partner") VALUES ($1, $2)`, userID, partner); err != nil {
				return errors.Wrap(err, "pgx.Tx.Exec()")
			}

			return nil
		},
		partnerOf: func(ctx context.Context, tx pgx.Tx, userID ccc.UUID) (string, bool, error) {
			var partner string
			err := tx.QueryRow(ctx, `SELECT "Partner" FROM "PartnerMembers" WHERE "UserId" = $1`, userID).Scan(&partner)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				return "", false, nil
			case err != nil:
				return "", false, errors.Wrap(err, "pgx.Row.Scan()")
			}

			return partner, true, nil
		},
		recordAttempt: func(ctx context.Context, tx pgx.Tx, subject, outcome string) error {
			if _, err := tx.Exec(ctx, `INSERT INTO "SignInAttempts" ("Subject", "Outcome") VALUES ($1, $2)`, subject, outcome); err != nil {
				return errors.Wrap(err, "pgx.Tx.Exec()")
			}

			return nil
		},
		tenantDeclaration: func(ctx context.Context, tx pgx.Tx, tenant accesstypes.Domain) (*signin.TenantDeclaration, error) {
			var (
				directories   string
				directoryOnly bool
			)
			err := tx.QueryRow(ctx, `SELECT "Directories", "DirectoryOnly" FROM "TenantDeclarations" WHERE "Tenant" = $1`, string(tenant)).Scan(&directories, &directoryOnly)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				return nil, nil
			case err != nil:
				return nil, errors.Wrap(err, "pgx.Row.Scan()")
			}

			return &signin.TenantDeclaration{Directories: parseDirectories(directories), DirectoryOnly: directoryOnly}, nil
		},
	},
}

// postgresDB is appDB over PostgreSQL.
type postgresDB struct {
	*dbinitiator.PostgresDatabase
}

func (db postgresDB) username(ctx context.Context, t *testing.T, userID ccc.UUID) string {
	t.Helper()

	var username string
	if err := db.QueryRow(ctx, `SELECT "Username" FROM "SessionUsers" WHERE "Id" = $1`, userID).Scan(&username); err != nil {
		t.Fatalf("read the user's username: %v", err)
	}

	return username
}

func (db postgresDB) attemptOutcome(ctx context.Context, t *testing.T, subject string) string {
	t.Helper()

	var outcome string
	err := db.QueryRow(ctx, `SELECT "Outcome" FROM "SignInAttempts" WHERE "Subject" = $1`, subject).Scan(&outcome)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	if err != nil {
		t.Fatalf("read the attempt's outcome: %v", err)
	}

	return outcome
}

func (db postgresDB) disableUser(ctx context.Context, t *testing.T, userID ccc.UUID) {
	t.Helper()

	if _, err := db.Exec(ctx, `UPDATE "SessionUsers" SET "Disabled" = TRUE WHERE "Id" = $1`, userID); err != nil {
		t.Fatalf("disable the user: %v", err)
	}
}

func (db postgresDB) hasUser(ctx context.Context, t *testing.T, username string) bool {
	t.Helper()

	var exists bool
	if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM "SessionUsers" WHERE "Username" = $1)`, username).Scan(&exists); err != nil {
		t.Fatalf("look the user up: %v", err)
	}

	return exists
}

func (db postgresDB) declareTenant(ctx context.Context, t *testing.T, tenant string, directoryOnly bool, directories ...signin.Directory) {
	t.Helper()

	if _, err := db.Exec(ctx, `INSERT INTO "TenantDeclarations" ("Tenant", "Directories", "DirectoryOnly") VALUES ($1, $2, $3)
		ON CONFLICT ("Tenant") DO UPDATE SET "Directories" = EXCLUDED."Directories", "DirectoryOnly" = EXCLUDED."DirectoryOnly"`,
		tenant, renderDirectories(directories), directoryOnly); err != nil {
		t.Fatalf("declare the tenant: %v", err)
	}
}

var spannerBackend = backend[*spanner.ReadWriteTransaction]{
	name: "spanner",
	newStore: func(ctx context.Context, t *testing.T) (appDB, *sessionstorage.Auth[*spanner.ReadWriteTransaction]) {
		t.Helper()

		db := prepareSpanner(ctx, t, spannerSessions, spannerImpersonation, spannerAuth, spannerAppTables)
		events, impersonation := storeTables(t)

		return spannerDB{db.Client}, sessionstorage.NewSpannerAuth(db.Client, sessionstorage.WithAuthEvents(events), sessionstorage.WithImpersonation(impersonation))
	},
	// The hooks write with DML, not mutations: a mutation is buffered until the commit,
	// so a policy running in the same transaction could not read what a resolver wrote.
	rows: appRows[*spanner.ReadWriteTransaction]{
		addMember: func(ctx context.Context, tx *spanner.ReadWriteTransaction, userID ccc.UUID, partner string) error {
			stmt := spanner.Statement{
				SQL:    `INSERT INTO PartnerMembers (UserId, Partner) VALUES (@userId, @partner)`,
				Params: map[string]any{"userId": userID.String(), "partner": partner},
			}
			if _, err := tx.Update(ctx, stmt); err != nil {
				return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
			}

			return nil
		},
		partnerOf: func(ctx context.Context, tx *spanner.ReadWriteTransaction, userID ccc.UUID) (string, bool, error) {
			row, err := tx.ReadRow(ctx, "PartnerMembers", spanner.Key{userID.String()}, []string{"Partner"})
			if spanner.ErrCode(err) == codes.NotFound {
				return "", false, nil
			}
			if err != nil {
				return "", false, errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
			}
			var partner string
			if err := row.Column(0, &partner); err != nil {
				return "", false, errors.Wrap(err, "spanner.Row.Column()")
			}

			return partner, true, nil
		},
		recordAttempt: func(ctx context.Context, tx *spanner.ReadWriteTransaction, subject, outcome string) error {
			stmt := spanner.Statement{
				SQL:    `INSERT INTO SignInAttempts (Subject, Outcome) VALUES (@subject, @outcome)`,
				Params: map[string]any{"subject": subject, "outcome": outcome},
			}
			if _, err := tx.Update(ctx, stmt); err != nil {
				return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
			}

			return nil
		},
		tenantDeclaration: func(ctx context.Context, tx *spanner.ReadWriteTransaction, tenant accesstypes.Domain) (*signin.TenantDeclaration, error) {
			row, err := tx.ReadRow(ctx, "TenantDeclarations", spanner.Key{string(tenant)}, []string{"Directories", "DirectoryOnly"})
			if spanner.ErrCode(err) == codes.NotFound {
				return nil, nil
			}
			if err != nil {
				return nil, errors.Wrap(err, "spanner.ReadWriteTransaction.ReadRow()")
			}
			var (
				directories   string
				directoryOnly bool
			)
			if err := row.Columns(&directories, &directoryOnly); err != nil {
				return nil, errors.Wrap(err, "spanner.Row.Columns()")
			}

			return &signin.TenantDeclaration{Directories: parseDirectories(directories), DirectoryOnly: directoryOnly}, nil
		},
	},
}

// spannerDB is appDB over Spanner.
type spannerDB struct {
	*spanner.Client
}

func (db spannerDB) username(ctx context.Context, t *testing.T, userID ccc.UUID) string {
	t.Helper()

	row, err := db.Single().ReadRow(ctx, "SessionUsers", spanner.Key{userID.String()}, []string{"Username"})
	if err != nil {
		t.Fatalf("read the user's username: %v", err)
	}
	var username string
	if err := row.Column(0, &username); err != nil {
		t.Fatalf("read the user's username: %v", err)
	}

	return username
}

func (db spannerDB) attemptOutcome(ctx context.Context, t *testing.T, subject string) string {
	t.Helper()

	row, err := db.Single().ReadRow(ctx, "SignInAttempts", spanner.Key{subject}, []string{"Outcome"})
	if spanner.ErrCode(err) == codes.NotFound {
		return ""
	}
	if err != nil {
		t.Fatalf("read the attempt's outcome: %v", err)
	}
	var outcome string
	if err := row.Column(0, &outcome); err != nil {
		t.Fatalf("read the attempt's outcome: %v", err)
	}

	return outcome
}

func (db spannerDB) disableUser(ctx context.Context, t *testing.T, userID ccc.UUID) {
	t.Helper()

	m := spanner.Update("SessionUsers", []string{"Id", "Disabled"}, []any{userID.String(), true})
	if _, err := db.Apply(ctx, []*spanner.Mutation{m}); err != nil {
		t.Fatalf("disable the user: %v", err)
	}
}

func (db spannerDB) hasUser(ctx context.Context, t *testing.T, username string) bool {
	t.Helper()

	iter := db.Single().Query(ctx, spanner.Statement{
		SQL:    `SELECT COUNT(1) FROM SessionUsers WHERE Username = @username`,
		Params: map[string]any{"username": username},
	})
	defer iter.Stop()
	row, err := iter.Next()
	if err != nil {
		t.Fatalf("look the user up: %v", err)
	}
	var n int64
	if err := row.Column(0, &n); err != nil {
		t.Fatalf("look the user up: %v", err)
	}

	return n > 0
}

func (db spannerDB) declareTenant(ctx context.Context, t *testing.T, tenant string, directoryOnly bool, directories ...signin.Directory) {
	t.Helper()

	m := spanner.InsertOrUpdate("TenantDeclarations", []string{"Tenant", "Directories", "DirectoryOnly"}, []any{tenant, renderDirectories(directories), directoryOnly})
	if _, err := db.Apply(ctx, []*spanner.Mutation{m}); err != nil {
		t.Fatalf("declare the tenant: %v", err)
	}
}
