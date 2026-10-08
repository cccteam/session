package sessionstorage

import (
	"context"
	"testing"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
	gomock "go.uber.org/mock/gomock"
)

func spannerResolver(context.Context, *cloudspanner.ReadWriteTransaction, *sessioninfo.NewSessionRequest) (*Resolution, error) {
	return &Resolution{}, nil
}

func postgresResolver(context.Context, pgx.Tx, *sessioninfo.NewSessionRequest) (*Resolution, error) {
	return &Resolution{}, nil
}

// TestNewIdentities validates the identities configuration for both backends: a valid
// table name and a resolver are required; the policy is optional.
func TestNewIdentities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tableName string
		noResolve bool
		wantErr   bool
	}{
		{name: "a valid table and resolver", tableName: "PartnerSessionIdentities"},
		{name: "an invalid table name is refused", tableName: "Session Identities; DROP", wantErr: true},
		{name: "a missing resolver is refused", tableName: "SessionIdentities", noResolve: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var sr SpannerAccountResolver = spannerResolver
			var pr PostgresAccountResolver = postgresResolver
			if tt.noResolve {
				sr, pr = nil, nil
			}

			if _, err := NewSpannerIdentities(tt.tableName, sr, nil); (err != nil) != tt.wantErr {
				t.Errorf("NewSpannerIdentities() error = %v, wantErr %v", err, tt.wantErr)
			}
			if _, err := NewPostgresIdentities(tt.tableName, pr, nil); (err != nil) != tt.wantErr {
				t.Errorf("NewPostgresIdentities() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	if _, err := NewAuthEventsTable("bad name"); err == nil {
		t.Error("NewAuthEventsTable(\"bad name\") error = nil, want refused")
	}
}

// TestAccounts_IdentitiesEnabled proves WithSpannerIdentities / WithPostgresIdentities
// attach the configuration to account storage, and that storage without it reports so.
func TestAccounts_IdentitiesEnabled(t *testing.T) {
	t.Parallel()

	spannerCfg, err := NewSpannerIdentities("SessionIdentities", spannerResolver, nil)
	if err != nil {
		t.Fatal(err)
	}
	postgresCfg, err := NewPostgresIdentities("SessionIdentities", postgresResolver, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		store *Accounts
		want  bool
	}{
		{name: "Spanner with identities", store: NewSpannerAccounts(nil, WithSpannerIdentities(spannerCfg)), want: true},
		{name: "Postgres with identities", store: NewPostgresAccounts(nil, WithPostgresIdentities(postgresCfg)), want: true},
		{name: "Spanner without", store: NewSpannerAccounts(nil)},
		{name: "Postgres without", store: NewPostgresAccounts(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.store.IdentitiesEnabled(); got != tt.want {
				t.Errorf("IdentitiesEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestResolution_DriverMapping proves the public outcomes and answers reach the drivers
// unchanged: the outcome values line up and every field is carried.
func TestResolution_DriverMapping(t *testing.T) {
	t.Parallel()

	outcomes := map[IdentityOutcome]dbtype.IdentityOutcome{
		RejectIdentity: dbtype.RejectIdentity, LinkIdentity: dbtype.LinkIdentity,
		ProvisionAccount: dbtype.ProvisionAccount, RequireConfirmation: dbtype.RequireConfirmation,
	}
	for public, driver := range outcomes {
		if got := driverResolution(&Resolution{Outcome: public}).Outcome; got != driver {
			t.Errorf("identity outcome %d maps to %d, want %d", public, got, driver)
		}
	}
	policies := map[PolicyOutcome]dbtype.PolicyOutcome{DenySignIn: dbtype.DenySignIn, AllowSignIn: dbtype.AllowSignIn, RequireMFA: dbtype.RequireMFA}
	for public, driver := range policies {
		if got := driverDecision(&SignInDecision{Outcome: public}).Outcome; got != driver {
			t.Errorf("policy outcome %d maps to %d, want %d", public, got, driver)
		}
	}

	userID := ccc.Must(ccc.NewUUID())
	newUser := &InsertSessionUser{Username: "new@example.com"}
	got := driverResolution(&Resolution{Outcome: ProvisionAccount, UserID: userID, NewUser: newUser, Tenant: "t", TrustedForLinking: true, Refusal: "x"})
	if got.UserID != userID || got.NewUser != newUser || got.Tenant != "t" || !got.TrustedForLinking || got.Refusal != "x" {
		t.Errorf("driverResolution() = %+v, want every field carried", got)
	}
	if driverResolution(nil) != nil || driverDecision(nil) != nil {
		t.Error("a nil answer must stay nil, which the drivers treat as reject / deny")
	}
}

// TestAccounts_StoreMethods proves each Accounts method maps the driver's rows to the
// public type and propagates the driver's errors with their class.
func TestAccounts_StoreMethods(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	link := &dbtype.SessionIdentity{ID: ccc.Must(ccc.NewUUID()), UserID: userID, Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "sub"}
	identity := &sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "sub"}
	event := sessioninfo.AuthEvent{Method: "email-otp"}
	refused := httpio.NewConflictMessageWithError(ErrLastSignInMethod, "last")

	tests := []struct {
		name    string
		prepare func(db *Mockdb)
		call    func(ctx context.Context, a *Accounts) (any, error)
		want    any
		wantErr error
	}{
		{
			name: "Identity maps the link",
			prepare: func(db *Mockdb) {
				db.EXPECT().Identity(gomock.Any(), sessioninfo.MethodWorkOS, "conn", "sub").Return(link, nil)
			},
			call: func(ctx context.Context, a *Accounts) (any, error) {
				return a.Identity(ctx, sessioninfo.MethodWorkOS, "conn", "sub")
			},
			want: (*SessionIdentity)(link),
		},
		{
			name: "IdentitiesByUser maps every link",
			prepare: func(db *Mockdb) {
				db.EXPECT().IdentitiesByUser(gomock.Any(), userID).Return([]*dbtype.SessionIdentity{link}, nil)
			},
			call: func(ctx context.Context, a *Accounts) (any, error) { return a.IdentitiesByUser(ctx, userID) },
			want: []*SessionIdentity{(*SessionIdentity)(link)},
		},
		{
			name:    "LinkIdentity maps the new link",
			prepare: func(db *Mockdb) { db.EXPECT().LinkIdentity(gomock.Any(), userID, identity, "tenant").Return(link, nil) },
			call: func(ctx context.Context, a *Accounts) (any, error) {
				return a.LinkIdentity(ctx, userID, identity, "tenant")
			},
			want: (*SessionIdentity)(link),
		},
		{
			name:    "UnlinkIdentity propagates the last-means-of-sign-in refusal",
			prepare: func(db *Mockdb) { db.EXPECT().UnlinkIdentity(gomock.Any(), link.ID).Return(refused) },
			call:    func(ctx context.Context, a *Accounts) (any, error) { return nil, a.UnlinkIdentity(ctx, link.ID) },
			wantErr: ErrLastSignInMethod,
		},
		{
			name:    "DestroyUserSessions forwards the account",
			prepare: func(db *Mockdb) { db.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil) },
			call:    func(ctx context.Context, a *Accounts) (any, error) { return nil, a.DestroyUserSessions(ctx, userID) },
		},
		{
			name:    "AppendAuthEvent forwards the event",
			prepare: func(db *Mockdb) { db.EXPECT().AppendAuthEvent(gomock.Any(), userID, &event).Return(nil) },
			call: func(ctx context.Context, a *Accounts) (any, error) {
				return nil, a.AppendAuthEvent(ctx, userID, &event)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			db := NewMockdb(ctrl)
			tt.prepare(db)
			a := &Accounts{PasswordAuth: &PasswordAuth{sessionStorage: sessionStorage{db: db}}}

			got, err := tt.call(t.Context(), a)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) || !httpio.HasConflict(err) {
					t.Errorf("error = %v, want %v as a Conflict", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if tt.want != nil {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("result mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
