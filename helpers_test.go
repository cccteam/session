package session

import (
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

func newPreauthStoreMock(ctrl *gomock.Controller) *mock_sessionstorage.MockPreauthStore {
	storage := mock_sessionstorage.NewMockPreauthStore(ctrl)
	storage.EXPECT().CustomUserDataType().Return(nil).AnyTimes()
	storage.EXPECT().OIDCUsersEnabled().Return(false).AnyTimes()

	return storage
}
