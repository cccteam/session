package postgres

import (
	"context"
	"testing"
)

func TestClient_FullMigration(t *testing.T) {
	t.Parallel()

	type args struct {
		sourceURL string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "FullMigration",
			args: args{
				sourceURL: "file://../schema/postgresql/oidc/migrations",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			db, err := prepareDatabase(ctx, t, tt.args.sourceURL)
			if (err != nil) != false {
				t.Fatalf("prepareDatabase() error = %v", err)
			}

			if err := db.MigrateDown(tt.args.sourceURL); err != nil {
				t.Fatalf("db.MigrateDown() error = %v, wantErr %v", err, false)
			}
		})
	}
}
