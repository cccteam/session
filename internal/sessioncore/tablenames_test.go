package sessioncore

import (
	"strings"
	"testing"

	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/testkey"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

// tableOption builds a table-name option the way the root package's options do.
func tableOption(option, name string, set func(b *basesession.BaseSession) func(string) error) BaseSessionOption {
	return func(b *basesession.BaseSession) {
		b.TableNames = append(b.TableNames, basesession.TableName{Option: option, Name: name, Set: set(b)})
	}
}

func TestNewBaseSession_TableNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		prepare    func(store *mock_sessionstorage.MockBaseStore)
		options    []BaseSessionOption
		wantErrHas string
	}{
		{
			name: "every table-name option reaches its store setter, in order",
			prepare: func(store *mock_sessionstorage.MockBaseStore) {
				gomock.InOrder(
					store.EXPECT().SetSessionTableName("GroupSessions").Return(nil),
					store.EXPECT().SetUserTableName("GroupUsers").Return(nil),
					store.EXPECT().SetOIDCUserTableName("GroupOIDCUsers").Return(nil),
				)
			},
			options: []BaseSessionOption{
				tableOption("WithSessionTableName", "GroupSessions", func(b *basesession.BaseSession) func(string) error { return b.Storage.SetSessionTableName }),
				tableOption("WithUserTableName", "GroupUsers", func(b *basesession.BaseSession) func(string) error { return b.Storage.SetUserTableName }),
				tableOption("WithOIDCUserTableName", "GroupOIDCUsers", func(b *basesession.BaseSession) func(string) error { return b.Storage.SetOIDCUserTableName }),
			},
		},
		{
			name: "a name the store refuses fails the constructor under the option's name",
			prepare: func(store *mock_sessionstorage.MockBaseStore) {
				store.EXPECT().SetUserTableName(`Staff"; DROP TABLE`).Return(errors.New("not an identifier"))
			},
			options: []BaseSessionOption{
				tableOption("WithUserTableName", `Staff"; DROP TABLE`, func(b *basesession.BaseSession) func(string) error { return b.Storage.SetUserTableName }),
			},
			wantErrHas: "WithUserTableName()",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			store := mock_sessionstorage.NewMockBaseStore(ctrl)
			tt.prepare(store)

			_, _, err := NewBaseSession(store, testkey.CookieKey, tt.options)
			if (err != nil) != (tt.wantErrHas != "") {
				t.Fatalf("NewBaseSession() error = %v, want error %v", err, tt.wantErrHas != "")
			}
			if err != nil && !strings.Contains(err.Error(), tt.wantErrHas) {
				t.Errorf("NewBaseSession() error = %v, want it to name %s", err, tt.wantErrHas)
			}
		})
	}
}
