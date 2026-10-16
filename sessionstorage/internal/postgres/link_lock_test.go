package postgres

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/drivertest"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestSessionStorageDriver_LockUserIn proves the lock a link decision takes on the user
// row: a second link decision for the user waits until the first ends and then sees its
// link, while a session insert for the user is not held.
func TestSessionStorageDriver_LockUserIn(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	db, err := prepareDatabase(ctx, t, authSources(drivertest.Auth)...)
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}
	d := NewSessionStorageDriver(db.Pool)
	d.EnableAuth()
	user, err := d.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "locked@lakeside.edu"}, nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	identity := &sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn_lakeside", Subject: "idp_locked", Email: "locked@lakeside.edu"}

	first, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	defer func() { _ = first.Rollback(ctx) }()
	if _, err := d.LockUserIn(ctx, first, user.ID); err != nil {
		t.Fatalf("LockUserIn() in the first transaction error = %v", err)
	}

	// Another link decision cannot take the lock while the first holds it.
	second, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	// Rolled back on every path: a transaction left open would hold the test database.
	defer func() { _ = second.Rollback(ctx) }()
	if _, err := second.Exec(ctx, "SET LOCAL lock_timeout = '200ms'"); err != nil {
		t.Fatalf("SET LOCAL lock_timeout error = %v", err)
	}
	_, err = d.LockUserIn(ctx, second, user.ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != pgerrcode.LockNotAvailable {
		t.Fatalf("LockUserIn() while another link decision holds the user = %v, want lock_not_available", err)
	}
	if err := second.Rollback(ctx); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}

	// A session insert for the user is not held: its foreign key takes FOR KEY SHARE.
	sessionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	now := time.Now()
	req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID}
	if _, err := d.InsertSession(sessionCtx, &dbtype.InsertSession{Username: user.Username, CreatedAt: now, UpdatedAt: now}, req); err != nil {
		t.Fatalf("InsertSession() while a link decision holds the user error = %v, want it not held", err)
	}

	// The first links and commits; a link decision after it sees the link.
	if _, err := d.LinkIdentityIn(ctx, first, user.ID, identity, "", now); err != nil {
		t.Fatalf("LinkIdentityIn() error = %v", err)
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	third, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	defer func() { _ = third.Rollback(ctx) }()
	if _, err := d.LockUserIn(ctx, third, user.ID); err != nil {
		t.Fatalf("LockUserIn() after the first committed error = %v", err)
	}
	links, err := d.IdentitiesByUserIn(ctx, third, user.ID)
	if err != nil {
		t.Fatalf("IdentitiesByUserIn() error = %v", err)
	}
	if len(links) != 1 || links[0].Connection != identity.Connection {
		t.Errorf("IdentitiesByUserIn() = %+v, want the first transaction's link", links)
	}
}

// TestSessionStorageDriver_LinkDeadlockRunsOnceMore proves the retry behind a deadlock:
// two sign-ins whose resolver shares the user row's lock before the link decision locks
// it deadlock, PostgreSQL ends one, and that one runs its resolution once more, sees the
// winner's link and is refused across connections.
func TestSessionStorageDriver_LinkDeadlockRunsOnceMore(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	db, err := prepareDatabase(ctx, t, authSources(drivertest.AuthWithAppTables)...)
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}
	d := NewSessionStorageDriver(db.Pool)
	d.EnableAuth()
	user, err := d.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "deadlock@lakeside.edu"}, nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	// The first two resolutions each share the user row's lock, then wait for each
	// other, so both hold it when their link decisions ask for the stronger lock.
	var (
		runs    atomic.Int32
		barrier sync.WaitGroup
	)
	barrier.Add(2)
	resolve := func(ctx context.Context, tx drivertest.HookTx, _ *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		hook, ok := tx.(hookTx)
		if !ok {
			return nil, errors.Newf("hook transaction is %T, want hookTx", tx)
		}
		if _, err := hook.txn.Exec(ctx, `SELECT 1 FROM "SessionUsers" WHERE "Id" = $1 FOR SHARE`, user.ID); err != nil {
			return nil, errors.Wrap(err, "pgx.Tx.Exec()")
		}
		if runs.Add(1) <= 2 {
			barrier.Done()
			barrier.Wait()
		}

		return signin.Link(user.ID, false), nil
	}
	signIn := drivertest.NewSignIn(d, drivertest.AuthConfig{Auth: true, Resolve: resolve}, func(txn pgx.Tx) drivertest.HookTx { return hookTx{txn} })

	identities := []*sessioninfo.Identity{
		{Method: sessioninfo.MethodWorkOS, Connection: "conn_lakeside", Subject: "idp_deadlock", Email: "deadlock@lakeside.edu"},
		{Method: sessioninfo.MethodWorkOS, Connection: "conn_riverside", Subject: "idp_deadlock", Email: "deadlock@lakeside.edu"},
	}
	var wg sync.WaitGroup
	errs := make([]error, len(identities))
	for i, identity := range identities {
		wg.Go(func() {
			now := time.Now()
			req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: identity.Email, Identity: identity}
			_, errs[i] = signIn(ctx, &dbtype.InsertSession{Username: identity.Email, CreatedAt: now, UpdatedAt: now}, req)
		})
	}
	wg.Wait()

	linked := 0
	for i, err := range errs {
		if err == nil {
			linked++

			continue
		}
		if sessioninfo.LoginRefusalCodeOf(err) != sessioninfo.RefusedIdentityRejected || !errors.Is(err, signin.ErrLinkCrossConnection) {
			t.Errorf("sign-in %d error = %v, want the cross-connection refusal after the rerun", i, err)
		}
	}
	if linked != 1 {
		t.Errorf("%d sign-ins linked, want exactly one", linked)
	}
	if got := runs.Load(); got != 3 {
		t.Errorf("the resolver ran %d times, want 3: both racing sign-ins and the loser's rerun", got)
	}
	links, err := d.IdentitiesByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("IdentitiesByUser() error = %v", err)
	}
	if len(links) != 1 {
		t.Errorf("IdentitiesByUser() = %d links, want 1", len(links))
	}
}
