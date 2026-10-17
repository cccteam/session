package sessionstorage

import (
	"context"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

// TestAuth_StoreMethods proves each Auth identity method maps the driver's rows to the
// public type and propagates the driver's errors with their class.
func TestAuth_StoreMethods(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	link := &dbtype.SessionIdentity{ID: ccc.Must(ccc.NewUUID()), UserID: userID, Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "sub"}
	identity := &sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "sub"}
	event := sessioninfo.AuthEvent{Method: "email-otp"}
	refused := httpio.NewConflictMessageWithError(ErrLastSignInMethod, "last")

	tests := []struct {
		name    string
		prepare func(db *Mockdb)
		call    func(ctx context.Context, a *Auth[struct{}]) (any, error)
		want    any
		wantErr error
	}{
		{
			name: "Identity maps the link",
			prepare: func(db *Mockdb) {
				db.EXPECT().Identity(gomock.Any(), sessioninfo.MethodWorkOS, "conn", "sub").Return(link, nil)
			},
			call: func(ctx context.Context, a *Auth[struct{}]) (any, error) {
				return a.Identity(ctx, sessioninfo.MethodWorkOS, "conn", "sub")
			},
			want: (*SessionIdentity)(link),
		},
		{
			name: "IdentitiesByUser maps every link",
			prepare: func(db *Mockdb) {
				db.EXPECT().IdentitiesByUser(gomock.Any(), userID).Return([]*dbtype.SessionIdentity{link}, nil)
			},
			call: func(ctx context.Context, a *Auth[struct{}]) (any, error) { return a.IdentitiesByUser(ctx, userID) },
			want: []*SessionIdentity{(*SessionIdentity)(link)},
		},
		{
			name:    "LinkIdentity maps the new link",
			prepare: func(db *Mockdb) { db.EXPECT().LinkIdentity(gomock.Any(), userID, identity, "tenant").Return(link, nil) },
			call: func(ctx context.Context, a *Auth[struct{}]) (any, error) {
				return a.LinkIdentity(ctx, userID, identity, "tenant")
			},
			want: (*SessionIdentity)(link),
		},
		{
			name:    "UnlinkIdentity propagates the last-means-of-sign-in refusal",
			prepare: func(db *Mockdb) { db.EXPECT().UnlinkIdentity(gomock.Any(), link.ID).Return(refused) },
			call:    func(ctx context.Context, a *Auth[struct{}]) (any, error) { return nil, a.UnlinkIdentity(ctx, link.ID) },
			wantErr: ErrLastSignInMethod,
		},
		{
			name:    "DestroyUserSessions forwards the user",
			prepare: func(db *Mockdb) { db.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil) },
			call: func(ctx context.Context, a *Auth[struct{}]) (any, error) {
				return nil, a.DestroyUserSessions(ctx, userID)
			},
		},
		{
			name:    "AppendAuthEvent forwards the event",
			prepare: func(db *Mockdb) { db.EXPECT().AppendAuthEvent(gomock.Any(), userID, &event).Return(nil) },
			call: func(ctx context.Context, a *Auth[struct{}]) (any, error) {
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
			a := &Auth[struct{}]{userStorage: userStorage{sessionStorage: sessionStorage{db: db}}}

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
