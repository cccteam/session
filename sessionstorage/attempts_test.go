package sessionstorage

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/session/internal/dbtype"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

// TestAuth_SignInAttempts proves the store's attempt methods map to the driver's and
// propagate its errors: the record read as the driver answers it, a failure recorded
// at the time of the call under the limit the Auth gave, a clear, and the table name.
func TestAuth_SignInAttempts(t *testing.T) {
	t.Parallel()

	limit := SignInAttemptLimit{Failures: 5, Window: 15 * time.Minute, Lock: 15 * time.Minute}
	record := &dbtype.SignInAttempts{Name: "pat", Failures: 2, WindowEndsAt: time.Now().Add(time.Hour)}

	tests := []struct {
		name    string
		prepare func(mockDB *Mockdb)
		run     func(ctx context.Context, store *Auth[struct{}]) (*SignInAttempts, error)
		want    *SignInAttempts
		wantErr bool
	}{
		{
			name: "SignInAttempts answers the driver's record",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().SignInAttempts(gomock.Any(), "pat").Return(record, nil)
			},
			run: func(ctx context.Context, store *Auth[struct{}]) (*SignInAttempts, error) {
				return store.SignInAttempts(ctx, "pat")
			},
			want: record,
		},
		{
			name: "SignInAttempts propagates the driver's error",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().SignInAttempts(gomock.Any(), "pat").Return(nil, errors.New("db error"))
			},
			run: func(ctx context.Context, store *Auth[struct{}]) (*SignInAttempts, error) {
				return store.SignInAttempts(ctx, "pat")
			},
			wantErr: true,
		},
		{
			name: "RecordSignInFailure hands the driver the limit and the time of the call",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().RecordSignInFailure(gomock.Any(), "pat", gomock.Any(), limit).DoAndReturn(
					func(_ context.Context, _ string, now time.Time, _ dbtype.SignInAttemptLimit) (*dbtype.SignInAttempts, error) {
						if since := time.Since(now); since < 0 || since > time.Minute {
							t.Errorf("RecordSignInFailure() now = %v, want the time of the call", now)
						}

						return record, nil
					})
			},
			run: func(ctx context.Context, store *Auth[struct{}]) (*SignInAttempts, error) {
				return store.RecordSignInFailure(ctx, "pat", limit)
			},
			want: record,
		},
		{
			name: "RecordSignInFailure propagates the driver's error",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().RecordSignInFailure(gomock.Any(), "pat", gomock.Any(), limit).Return(nil, errors.New("db error"))
			},
			run: func(ctx context.Context, store *Auth[struct{}]) (*SignInAttempts, error) {
				return store.RecordSignInFailure(ctx, "pat", limit)
			},
			wantErr: true,
		},
		{
			name: "ClearSignInAttempts clears through the driver",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().ClearSignInAttempts(gomock.Any(), "pat").Return(nil)
			},
			run: func(ctx context.Context, store *Auth[struct{}]) (*SignInAttempts, error) {
				return nil, store.ClearSignInAttempts(ctx, "pat")
			},
		},
		{
			name: "ClearSignInAttempts propagates the driver's error",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().ClearSignInAttempts(gomock.Any(), "pat").Return(errors.New("db error"))
			},
			run: func(ctx context.Context, store *Auth[struct{}]) (*SignInAttempts, error) {
				return nil, store.ClearSignInAttempts(ctx, "pat")
			},
			wantErr: true,
		},
		{
			name: "SetSignInAttemptsTableName names the driver's table and propagates its refusal",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().SetSignInAttemptsTableName("Attempts").Return(nil)
				mockDB.EXPECT().SetSignInAttemptsTableName("bad name").Return(errors.New("not an identifier"))
			},
			run: func(_ context.Context, store *Auth[struct{}]) (*SignInAttempts, error) {
				if err := store.SetSignInAttemptsTableName("Attempts"); err != nil {
					return nil, err
				}

				return nil, store.SetSignInAttemptsTableName("bad name")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockDB := NewMockdb(ctrl)
			store := &Auth[struct{}]{userStorage: userStorage{sessionStorage: sessionStorage{db: mockDB}}}
			tt.prepare(mockDB)

			got, err := tt.run(context.Background(), store)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("record mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
