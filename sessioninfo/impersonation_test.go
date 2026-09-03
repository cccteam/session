package sessioninfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
)

func ctxWithSession(username string, imp *Impersonation) context.Context {
	return context.WithValue(context.Background(), CtxSessionInfo, &SessionData{
		SessionInfo:   &SessionInfo{ID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), Username: username},
		Impersonation: imp,
	})
}

func TestImpersonationAccessors(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))
	sourceID := ccc.Must(ccc.UUIDFromString("7a1d5f6e-0c2b-4a3e-9d8f-1b2c3d4e5f60"))

	userImp := &Impersonation{
		SessionID: sessionID,
		Actor:     "alice@example.com",
		Principal: accesstypes.UserPrincipal("bob@partner.org"),
		Mask:      accesstypes.MaskPermissions(accesstypes.List, accesstypes.Read),
	}
	roleImp := &Impersonation{
		SessionID:       sessionID,
		Actor:           "alice@example.com",
		ActorRealm:      "admin-portal",
		SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true},
		Principal:       accesstypes.RolePrincipal("PartnerViewer"),
	}

	tests := []struct {
		name          string
		ctx           context.Context
		wantImp       *Impersonation
		wantPrincipal accesstypes.Principal
		wantActor     string
		wantMask      accesstypes.PermissionMask
		wantKind      string
		wantName      string
		wantAttrs     []Attribute
	}{
		{
			name:          "normal session",
			ctx:           ctxWithSession("alice@example.com", nil),
			wantPrincipal: accesstypes.UserPrincipal("alice@example.com"),
			wantActor:     "alice@example.com",
		},
		{
			name:          "impersonated user, read-only",
			ctx:           ctxWithSession("bob@partner.org", userImp),
			wantImp:       userImp,
			wantPrincipal: accesstypes.UserPrincipal("bob@partner.org"),
			wantActor:     "alice@example.com",
			wantMask:      accesstypes.MaskPermissions(accesstypes.List, accesstypes.Read),
			wantKind:      "User",
			wantName:      "bob@partner.org",
			wantAttrs: []Attribute{
				{Key: AttrImpersonationActor, Value: "alice@example.com"},
				{Key: AttrImpersonationPrincipalKind, Value: "User"},
				{Key: AttrImpersonationPrincipal, Value: "bob@partner.org"},
				{Key: AttrImpersonationMask, Value: "List,Read"},
				{Key: AttrImpersonationSessionID, Value: sessionID.String()},
			},
		},
		{
			name:          "impersonated role from another realm",
			ctx:           ctxWithSession("alice@example.com", roleImp),
			wantImp:       roleImp,
			wantPrincipal: accesstypes.RolePrincipal("PartnerViewer"),
			wantActor:     "alice@example.com",
			wantKind:      "Role",
			wantName:      "PartnerViewer",
			wantAttrs: []Attribute{
				{Key: AttrImpersonationActor, Value: "alice@example.com"},
				{Key: AttrImpersonationPrincipalKind, Value: "Role"},
				{Key: AttrImpersonationPrincipal, Value: "PartnerViewer"},
				{Key: AttrImpersonationMask, Value: "unrestricted"},
				{Key: AttrImpersonationSessionID, Value: sessionID.String()},
				{Key: AttrImpersonationActorRealm, Value: "admin-portal"},
				{Key: AttrImpersonationSourceSessionID, Value: sourceID.String()},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			imp, ok := ImpersonationFromCtx(tt.ctx)
			if ok != (tt.wantImp != nil) || imp != tt.wantImp {
				t.Errorf("ImpersonationFromCtx() = (%v, %v), want (%v, %v)", imp, ok, tt.wantImp, tt.wantImp != nil)
			}
			if got := PrincipalFromCtx(tt.ctx); got != tt.wantPrincipal {
				t.Errorf("PrincipalFromCtx() = %v, want %v", got, tt.wantPrincipal)
			}
			if got := ActorFromCtx(tt.ctx); got != tt.wantActor {
				t.Errorf("ActorFromCtx() = %q, want %q", got, tt.wantActor)
			}
			if got := MaskFromCtx(tt.ctx); got.String() != tt.wantMask.String() {
				t.Errorf("MaskFromCtx() = %v, want %v", got, tt.wantMask)
			}
			if imp == nil {
				return
			}
			if got := imp.PrincipalKind(); got != tt.wantKind {
				t.Errorf("PrincipalKind() = %q, want %q", got, tt.wantKind)
			}
			if got := imp.PrincipalName(); got != tt.wantName {
				t.Errorf("PrincipalName() = %q, want %q", got, tt.wantName)
			}
			if diff := cmp.Diff(tt.wantAttrs, imp.Attributes()); diff != "" {
				t.Errorf("Attributes() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestImpersonationFromCtx_PanicsWithoutSession(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("ImpersonationFromCtx() did not panic without a session in the context")
		}
	}()

	ImpersonationFromCtx(context.Background())
}

func TestImpersonationFromRequest(t *testing.T) {
	t.Parallel()

	imp := &Impersonation{Actor: "alice", Principal: accesstypes.RolePrincipal("Editor"), StartedAt: time.Now()}
	r := httptest.NewRequestWithContext(ctxWithSession("alice", imp), http.MethodGet, "/", http.NoBody)

	got, ok := ImpersonationFromRequest(r)
	if !ok || got != imp {
		t.Errorf("ImpersonationFromRequest() = (%v, %v), want (%v, true)", got, ok, imp)
	}
}
