package session

import (
	"reflect"
	"testing"

	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

// testData is the custom session data struct used by the root package tests.
type testData struct {
	Tenant string `spanner:"TenantId" db:"TenantId"`
}

type otherTestData struct {
	Partner string `spanner:"PartnerId" db:"PartnerId"`
}

func Test_verifyCustomDataType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		verify  func(storage *mock_sessionstorage.MockPreauthStore) error
		prepare func(storage *mock_sessionstorage.MockPreauthStore)
		wantErr bool
	}{
		{
			name: "NoCustomData skips the check",
			verify: func(storage *mock_sessionstorage.MockPreauthStore) error {
				return verifyCustomDataType[NoCustomData](storage)
			},
		},
		{
			name: "matching config type",
			verify: func(storage *mock_sessionstorage.MockPreauthStore) error {
				return verifyCustomDataType[testData](storage)
			},
			prepare: func(storage *mock_sessionstorage.MockPreauthStore) {
				storage.EXPECT().CustomDataType().Return(reflect.TypeFor[testData]())
			},
		},
		{
			name: "mismatched config type",
			verify: func(storage *mock_sessionstorage.MockPreauthStore) error {
				return verifyCustomDataType[testData](storage)
			},
			prepare: func(storage *mock_sessionstorage.MockPreauthStore) {
				storage.EXPECT().CustomDataType().Return(reflect.TypeFor[otherTestData]())
			},
			wantErr: true,
		},
		{
			name: "no custom session data config",
			verify: func(storage *mock_sessionstorage.MockPreauthStore) error {
				return verifyCustomDataType[testData](storage)
			},
			prepare: func(storage *mock_sessionstorage.MockPreauthStore) {
				storage.EXPECT().CustomDataType().Return(nil)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockPreauthStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(storage)
			}

			if err := tt.verify(storage); (err != nil) != tt.wantErr {
				t.Errorf("verifyCustomDataType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_eraseMutate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		data       any
		mutate     func(data *testData) error
		wantErr    bool
		wantTenant string
	}{
		{
			name: "matching type is mutated",
			data: &testData{Tenant: "tenant-1"},
			mutate: func(data *testData) error {
				data.Tenant = "tenant-2"

				return nil
			},
			wantTenant: "tenant-2",
		},
		{
			name: "mutate error passes through",
			data: &testData{Tenant: "tenant-1"},
			mutate: func(_ *testData) error {
				return errors.New("mutate failure")
			},
			wantErr:    true,
			wantTenant: "tenant-1",
		},
		{
			name: "mismatched type errors without calling mutate",
			data: &otherTestData{Partner: "partner-1"},
			mutate: func(_ *testData) error {
				return errors.New("mutate must not be called for a mismatched type")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := eraseMutate(tt.mutate)(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("eraseMutate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if data, ok := tt.data.(*testData); ok && data.Tenant != tt.wantTenant {
				t.Errorf("eraseMutate() data.Tenant = %q, want %q", data.Tenant, tt.wantTenant)
			}
		})
	}
}
