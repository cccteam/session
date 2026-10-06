package session

import (
	"context"

	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	gomock "go.uber.org/mock/gomock"
)

// The session-type constructors probe the storage for misconfiguration (custom user
// data type link, OIDC-only features on non-OIDC storage). These helpers return store
// mocks with those probes defaulted to "not configured" so tests exercising other
// behavior construct session types without boilerplate; tests targeting the probes
// build raw mocks with explicit expectations instead.

func newPasswordStoreMock(ctrl *gomock.Controller) *mock_sessionstorage.MockPasswordAuthStore {
	storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
	storage.EXPECT().CustomUserDataType().Return(nil).AnyTimes()
	storage.EXPECT().UserDataLoginHookConfigured().Return(false).AnyTimes()
	storage.EXPECT().OIDCUsersEnabled().Return(false).AnyTimes()

	return storage
}

func newOIDCStoreMock(ctrl *gomock.Controller) *mock_sessionstorage.MockOIDCStore {
	storage := mock_sessionstorage.NewMockOIDCStore(ctrl)
	storage.EXPECT().CustomUserDataType().Return(nil).AnyTimes()
	storage.EXPECT().OIDCUsersEnabled().Return(false).AnyTimes()

	return storage
}

func newGoogleOIDCStoreMock(ctrl *gomock.Controller) *mock_sessionstorage.MockGoogleOIDCStore {
	storage := mock_sessionstorage.NewMockGoogleOIDCStore(ctrl)
	storage.EXPECT().CustomUserDataType().Return(nil).AnyTimes()
	storage.EXPECT().OIDCUsersEnabled().Return(false).AnyTimes()

	return storage
}

func newPreauthStoreMock(ctrl *gomock.Controller) *mock_sessionstorage.MockPreauthStore {
	storage := mock_sessionstorage.NewMockPreauthStore(ctrl)
	storage.EXPECT().CustomUserDataType().Return(nil).AnyTimes()
	storage.EXPECT().OIDCUsersEnabled().Return(false).AnyTimes()

	return storage
}

// fakeGroups stands in for the Cloud Identity lookup: direct and nested name the groups
// each member gets from the lookup of that reach, err fails every lookup, and mode and
// token record the last call, so a test can see which lookup ran and with what.
type fakeGroups struct {
	direct, nested map[string][]string
	err            error
	mode           string
	token          string
}

func newFakeGroups() *fakeGroups {
	return &fakeGroups{direct: map[string][]string{}, nested: map[string][]string{}}
}

func (f *fakeGroups) DirectGroups(_ context.Context, token, member string) ([]string, error) {
	f.mode, f.token = lookupNameDirect, token

	return f.direct[member], f.err
}

func (f *fakeGroups) NestedGroups(_ context.Context, token, member string) ([]string, error) {
	f.mode, f.token = lookupNameNested, token

	return f.nested[member], f.err
}
