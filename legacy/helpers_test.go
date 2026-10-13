package legacy

import (
	"context"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session"
	"github.com/cccteam/session/internal/testkey"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	gomock "go.uber.org/mock/gomock"
)

const cookieKey = testkey.CookieKey

// testData is the custom session data struct used by the legacy package tests.
type testData struct {
	Tenant string `spanner:"TenantId" db:"TenantId"`
}

type otherTestData struct {
	Partner string `spanner:"PartnerId" db:"PartnerId"`
}

// The constructors probe the storage for misconfiguration (custom user data type link,
// OIDC-only features on non-OIDC storage). These helpers return store mocks with those
// probes defaulted to "not configured" so tests exercising other behavior construct
// session types without boilerplate; tests targeting the probes build raw mocks with
// explicit expectations instead.

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

func impersonatedCtx(sessionID ccc.UUID, username string, imp *sessioninfo.Impersonation) context.Context {
	ctx := context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID)

	return context.WithValue(ctx, sessioninfo.CtxSessionInfo, &sessioninfo.SessionData{
		SessionInfo:   &sessioninfo.SessionInfo{ID: sessionID, Username: username, UpdatedAt: time.Now()},
		Impersonation: imp,
	})
}

// liveSession is an ordinary, just-active session row for username.
func liveSession(id ccc.UUID, username string) *sessioninfo.SessionData {
	return &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: id, Username: username, UpdatedAt: time.Now()}}
}

// hookOrRecorder returns hook when set, otherwise a hook recording event kinds into seen.
func hookOrRecorder(hook session.ImpersonationAuditHook, seen *[]sessioninfo.ImpersonationEventKind) session.ImpersonationAuditHook {
	if hook != nil {
		return hook
	}

	return func(_ context.Context, event sessioninfo.ImpersonationEvent) error {
		*seen = append(*seen, event.Kind)

		return nil
	}
}

// assertErrorShape checks which httpio message class err carries.
func assertErrorShape(t *testing.T, err error, wantBadRequest, wantForbidden, wantUnauthorized bool) {
	t.Helper()

	if httpio.HasBadRequest(err) != wantBadRequest || httpio.HasForbidden(err) != wantForbidden || httpio.HasUnauthorized(err) != wantUnauthorized {
		t.Errorf("error = %v; want badRequest=%v forbidden=%v unauthorized=%v", err, wantBadRequest, wantForbidden, wantUnauthorized)
	}
}

// refusalCodeShape is what a refusal code looks like: a token, never a sentence.
var refusalCodeShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// assertRefusalQuery pins the wire contract of a refused login on the redirect the handler
// wrote: the Location's query has exactly the key code, and its value has the shape of a
// code, so no client text and no message key can ride along.
func assertRefusalQuery(t *testing.T, location string) {
	t.Helper()

	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", location, err)
	}
	q := u.Query()
	if len(q) != 1 || !q.Has("code") {
		t.Errorf("refused login Location %q: query keys = %v, want exactly [code]", location, keys(q))
	}
	if code := q.Get("code"); !refusalCodeShape.MatchString(code) {
		t.Errorf("refused login Location %q: code = %q, want a code, not text", location, code)
	}
}

func keys(q url.Values) []string {
	out := make([]string, 0, len(q))
	for k := range q {
		out = append(out, k)
	}

	return out
}
