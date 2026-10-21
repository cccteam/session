package signin

import (
	"context"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// fakeTx stands in for a storage's transaction type.
type fakeTx struct{}

// fakeDeclarations stands in for the application's reader of a tenant's declaration:
// declared holds each tenant's declaration (a tenant missing from it declares
// nothing), err fails every read, and asked records the tenants read, in order.
type fakeDeclarations struct {
	declared map[accesstypes.Domain]*TenantDeclaration
	err      error
	asked    []accesstypes.Domain
}

func (f *fakeDeclarations) read(_ context.Context, _ fakeTx, tenant accesstypes.Domain) (*TenantDeclaration, error) {
	f.asked = append(f.asked, tenant)
	if f.err != nil {
		return nil, f.err
	}

	return f.declared[tenant], nil
}

// The identities a sign-in may carry: through the Lakeside Entra tenant, through the
// Lakeside Google Workspace, by password, and the application's own.
var (
	entraIdentity     = &sessioninfo.Identity{Method: sessioninfo.MethodAzure, Connection: "tid-lakeside", Subject: "oid-pat"}
	workspaceIdentity = &sessioninfo.Identity{Method: sessioninfo.MethodGoogle, Connection: "lakeside", Subject: "sub-pat"}
	passwordIdentity  = &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: "user-id"}
	ownIdentity       = &sessioninfo.Identity{Method: sessioninfo.MethodApplication, Subject: "user-id"}
	lakesideEntra     = Directory{Method: sessioninfo.MethodAzure, Connection: "tid-lakeside"}
)

func TestTenantDeclaration_Admits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		declaration *TenantDeclaration
		method      sessioninfo.AuthMethod
		connection  string
		want        bool
	}{
		{
			name:   "a tenant that declares nothing admits a password",
			method: sessioninfo.MethodPassword,
			want:   true,
		},
		{
			name:       "a tenant that declares nothing admits no directory",
			method:     sessioninfo.MethodAzure,
			connection: "tid-lakeside",
			want:       false,
		},
		{
			name:        "an empty declaration is a tenant that declares nothing",
			declaration: &TenantDeclaration{},
			method:      sessioninfo.MethodPassword,
			want:        true,
		},
		{
			name:        "a declared directory admits a sign-in through it",
			declaration: &TenantDeclaration{Directories: []Directory{lakesideEntra}},
			method:      sessioninfo.MethodAzure,
			connection:  "tid-lakeside",
			want:        true,
		},
		{
			name:        "the same method through another connection is not the declared directory",
			declaration: &TenantDeclaration{Directories: []Directory{lakesideEntra}},
			method:      sessioninfo.MethodAzure,
			connection:  "tid-riverside",
			want:        false,
		},
		{
			name:        "another method with the same connection is not the declared directory",
			declaration: &TenantDeclaration{Directories: []Directory{lakesideEntra}},
			method:      sessioninfo.MethodGoogle,
			connection:  "tid-lakeside",
			want:        false,
		},
		{
			name:        "a second declared directory admits a sign-in through it",
			declaration: &TenantDeclaration{Directories: []Directory{lakesideEntra, {Method: sessioninfo.MethodGoogle, Connection: "lakeside"}}},
			method:      sessioninfo.MethodGoogle,
			connection:  "lakeside",
			want:        true,
		},
		{
			name:        "a tenant with a directory admits a password unless it is directory only",
			declaration: &TenantDeclaration{Directories: []Directory{lakesideEntra}},
			method:      sessioninfo.MethodPassword,
			want:        true,
		},
		{
			name:        "a directory-only tenant refuses a password",
			declaration: &TenantDeclaration{Directories: []Directory{lakesideEntra}, DirectoryOnly: true},
			method:      sessioninfo.MethodPassword,
			want:        false,
		},
		{
			name:        "a directory-only tenant admits its directory",
			declaration: &TenantDeclaration{Directories: []Directory{lakesideEntra}, DirectoryOnly: true},
			method:      sessioninfo.MethodAzure,
			connection:  "tid-lakeside",
			want:        true,
		},
		{
			name:        "a directory-only tenant refuses a session the application started itself",
			declaration: &TenantDeclaration{Directories: []Directory{lakesideEntra}, DirectoryOnly: true},
			method:      sessioninfo.MethodApplication,
			want:        false,
		},
		{
			name:        "a directory-only tenant refuses a step the application recorded under its own name",
			declaration: &TenantDeclaration{Directories: []Directory{lakesideEntra}, DirectoryOnly: true},
			method:      "magic-link",
			connection:  "app",
			want:        false,
		},
		{
			name:        "a tenant that is not directory only admits an impersonation",
			declaration: &TenantDeclaration{Directories: []Directory{lakesideEntra}},
			method:      sessioninfo.MethodImpersonation,
			connection:  "alice@example.com",
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.declaration.Admits(tt.method, tt.connection); got != tt.want {
				t.Errorf("Admits(%q, %q) = %v, want %v", tt.method, tt.connection, got, tt.want)
			}
		})
	}
}

func TestTenantPolicy(t *testing.T) {
	t.Parallel()

	global := accesstypes.GlobalPolicyScope()
	every := accesstypes.EveryDomainPolicyScope()
	lakeside := accesstypes.DomainPolicyScope("lakeside")
	riverside := accesstypes.DomainPolicyScope("riverside")
	member := []accesstypes.Role{"Member"}
	directoryOnly := &TenantDeclaration{Directories: []Directory{lakesideEntra}, DirectoryOnly: true}
	open := &TenantDeclaration{Directories: []Directory{lakesideEntra}}

	tests := []struct {
		name string
		// held are the memberships the role store answers; heldErr fails the read.
		held    accesstypes.RoleCollection
		heldErr error
		// roleNames is what the sign-in method asserted; nil when it synchronizes no
		// roles.
		roleNames []string
		identity  *sessioninfo.Identity
		declared  map[accesstypes.Domain]*TenantDeclaration
		readErr   error
		opts      []TenantPolicyOption
		// wantOutcome, wantCode and wantCause are the decision; wantErr a failed
		// sign-in instead.
		wantOutcome PolicyOutcome
		wantCode    sessioninfo.LoginRefusalCode
		wantCause   error
		wantErr     bool
		// wantRead are the tenants the reader was asked for, in order.
		wantRead []accesstypes.Domain
	}{
		{
			name:        "a global role admits a sign-in through a directory no tenant declares",
			held:        accesstypes.RoleCollection{global: {"Administrator"}},
			identity:    entraIdentity,
			wantOutcome: AllowSignIn,
		},
		{
			name:        "an every-domain role admits a password when every tenant is directory only",
			held:        accesstypes.RoleCollection{every: {"Auditor"}, lakeside: member},
			identity:    passwordIdentity,
			declared:    map[accesstypes.Domain]*TenantDeclaration{"lakeside": directoryOnly},
			wantOutcome: AllowSignIn,
		},
		{
			name:        "a sign-in whose method synchronizes roles is admitted without the store being asked",
			heldErr:     errors.New("the store was asked"),
			roleNames:   []string{"Pilot"},
			identity:    entraIdentity,
			wantOutcome: AllowSignIn,
		},
		{
			name:        "a member of no tenant is refused with no_tenant",
			held:        accesstypes.RoleCollection{},
			identity:    entraIdentity,
			wantOutcome: DenySignIn,
			wantCode:    sessioninfo.RefusedNoTenant,
			wantCause:   ErrNoTenant,
		},
		{
			name:        "a membership with no role is no membership",
			held:        accesstypes.RoleCollection{lakeside: {}, global: {}},
			identity:    passwordIdentity,
			wantOutcome: DenySignIn,
			wantCode:    sessioninfo.RefusedNoTenant,
			wantCause:   ErrNoTenant,
		},
		{
			name:        "a member of no tenant is admitted with AdmitWithoutTenant, by password",
			held:        accesstypes.RoleCollection{},
			identity:    passwordIdentity,
			opts:        []TenantPolicyOption{AdmitWithoutTenant()},
			wantOutcome: AllowSignIn,
		},
		{
			name:        "a member of no tenant is admitted with AdmitWithoutTenant, through a directory no tenant declares",
			held:        accesstypes.RoleCollection{},
			identity:    workspaceIdentity,
			opts:        []TenantPolicyOption{AdmitWithoutTenant()},
			wantOutcome: AllowSignIn,
		},
		{
			name:        "a sign-in through a directory one of the person's tenants declares is admitted",
			held:        accesstypes.RoleCollection{riverside: member, lakeside: member},
			identity:    entraIdentity,
			declared:    map[accesstypes.Domain]*TenantDeclaration{"riverside": open},
			wantOutcome: AllowSignIn,
			wantRead:    []accesstypes.Domain{"lakeside", "riverside"},
		},
		{
			name:        "a sign-in through a directory no tenant of the person declares is refused with connection_not_in_tenant",
			held:        accesstypes.RoleCollection{lakeside: member, riverside: member},
			identity:    workspaceIdentity,
			declared:    map[accesstypes.Domain]*TenantDeclaration{"lakeside": open, "riverside": directoryOnly},
			wantOutcome: DenySignIn,
			wantCode:    sessioninfo.RefusedConnectionNotInTenant,
			wantCause:   ErrConnectionNotInTenant,
			wantRead:    []accesstypes.Domain{"lakeside", "riverside"},
		},
		{
			name:        "a tenant that declares nothing admits no directory",
			held:        accesstypes.RoleCollection{lakeside: member},
			identity:    entraIdentity,
			wantOutcome: DenySignIn,
			wantCode:    sessioninfo.RefusedConnectionNotInTenant,
			wantCause:   ErrConnectionNotInTenant,
			wantRead:    []accesstypes.Domain{"lakeside"},
		},
		{
			name:        "a password is admitted when one tenant admits its people other than through its directory",
			held:        accesstypes.RoleCollection{lakeside: member, riverside: member},
			identity:    passwordIdentity,
			declared:    map[accesstypes.Domain]*TenantDeclaration{"lakeside": directoryOnly},
			wantOutcome: AllowSignIn,
			wantRead:    []accesstypes.Domain{"lakeside", "riverside"},
		},
		{
			name:        "a password is refused with directory_only when every tenant of the person is directory only",
			held:        accesstypes.RoleCollection{lakeside: member, riverside: member},
			identity:    passwordIdentity,
			declared:    map[accesstypes.Domain]*TenantDeclaration{"lakeside": directoryOnly, "riverside": {DirectoryOnly: true}},
			wantOutcome: DenySignIn,
			wantCode:    sessioninfo.RefusedDirectoryOnly,
			wantCause:   ErrDirectoryOnly,
			wantRead:    []accesstypes.Domain{"lakeside", "riverside"},
		},
		{
			name:        "a session the application starts itself is held to directory only like a password",
			held:        accesstypes.RoleCollection{lakeside: member},
			identity:    ownIdentity,
			declared:    map[accesstypes.Domain]*TenantDeclaration{"lakeside": directoryOnly},
			wantOutcome: DenySignIn,
			wantCode:    sessioninfo.RefusedDirectoryOnly,
			wantCause:   ErrDirectoryOnly,
			wantRead:    []accesstypes.Domain{"lakeside"},
		},
		{
			name:        "a session the application starts itself is admitted by a tenant that is not directory only",
			held:        accesstypes.RoleCollection{lakeside: member},
			identity:    ownIdentity,
			declared:    map[accesstypes.Domain]*TenantDeclaration{"lakeside": open},
			wantOutcome: AllowSignIn,
			wantRead:    []accesstypes.Domain{"lakeside"},
		},
		{
			name:        "the reader is asked tenant by tenant, in a fixed order, until one admits",
			held:        accesstypes.RoleCollection{riverside: member, lakeside: member, accesstypes.DomainPolicyScope("hilltop"): member},
			identity:    passwordIdentity,
			declared:    map[accesstypes.Domain]*TenantDeclaration{"hilltop": directoryOnly, "lakeside": directoryOnly},
			wantOutcome: AllowSignIn,
			wantRead:    []accesstypes.Domain{"hilltop", "lakeside", "riverside"},
		},
		{
			name:     "a role store error fails the sign-in",
			heldErr:  errors.New("store blip"),
			identity: passwordIdentity,
			wantErr:  true,
		},
		{
			name:     "a reader error fails the sign-in",
			held:     accesstypes.RoleCollection{lakeside: member},
			identity: passwordIdentity,
			readErr:  errors.New("row blip"),
			wantErr:  true,
			wantRead: []accesstypes.Domain{"lakeside"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			roles := &fakeRoleManager{held: tt.held, heldErr: tt.heldErr}
			reader := &fakeDeclarations{declared: tt.declared, err: tt.readErr}
			policy := TenantPolicy(roles, reader.read, tt.opts...)
			req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "pat@lakeside.edu", Identity: tt.identity, RoleNames: tt.roleNames}

			decision, err := policy(t.Context(), fakeTx{}, req)

			if (err != nil) != tt.wantErr {
				t.Fatalf("TenantPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.wantRead, reader.asked, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("tenants read mismatch (-want +got):\n%s", diff)
			}
			if tt.wantErr {
				return
			}
			if decision.Outcome() != tt.wantOutcome {
				t.Errorf("Outcome() = %v, want %v", decision.Outcome(), tt.wantOutcome)
			}
			if decision.Refusal() != tt.wantCode {
				t.Errorf("Refusal() = %q, want %q", decision.Refusal(), tt.wantCode)
			}
			if tt.wantCause != nil && !errors.Is(decision.Cause(), tt.wantCause) {
				t.Errorf("Cause() = %v, want %v", decision.Cause(), tt.wantCause)
			}
			if tt.wantCause == nil && decision.Cause() != nil {
				t.Errorf("Cause() = %v, want none", decision.Cause())
			}
		})
	}
}

func TestPolicy_Then(t *testing.T) {
	t.Parallel()

	answer := func(decision *Decision, asked *int) Policy[fakeTx] {
		return func(context.Context, fakeTx, *sessioninfo.NewSessionRequest) (*Decision, error) {
			*asked++

			return decision, nil
		}
	}
	fail := func(asked *int) Policy[fakeTx] {
		return func(context.Context, fakeTx, *sessioninfo.NewSessionRequest) (*Decision, error) {
			*asked++

			return nil, errors.New("rule blip")
		}
	}

	tests := []struct {
		name          string
		first         func(asked *int) Policy[fakeTx]
		next          func(asked *int) Policy[fakeTx]
		wantDecision  *Decision
		wantErr       bool
		wantNextAsked bool
	}{
		{
			name:          "the next rule decides after an Allow",
			first:         func(asked *int) Policy[fakeTx] { return answer(Allow(), asked) },
			next:          func(asked *int) Policy[fakeTx] { return answer(Deny("app_denied"), asked) },
			wantDecision:  Deny("app_denied"),
			wantNextAsked: true,
		},
		{
			name:          "an Allow from both allows",
			first:         func(asked *int) Policy[fakeTx] { return answer(Allow(), asked) },
			next:          func(asked *int) Policy[fakeTx] { return answer(Allow(), asked) },
			wantDecision:  Allow(),
			wantNextAsked: true,
		},
		{
			name:         "a Deny is answered as it is and the next rule is not asked",
			first:        func(asked *int) Policy[fakeTx] { return answer(denyBecause("no_tenant", ErrNoTenant), asked) },
			next:         func(asked *int) Policy[fakeTx] { return answer(Allow(), asked) },
			wantDecision: denyBecause("no_tenant", ErrNoTenant),
		},
		{
			name:         "a RequireMFA is answered as it is and the next rule is not asked",
			first:        func(asked *int) Policy[fakeTx] { return answer(RequireMFA("email-otp"), asked) },
			next:         func(asked *int) Policy[fakeTx] { return answer(Deny("app_denied"), asked) },
			wantDecision: RequireMFA("email-otp"),
		},
		{
			name:  "no decision denies and the next rule is not asked",
			first: func(asked *int) Policy[fakeTx] { return answer(nil, asked) },
			next:  func(asked *int) Policy[fakeTx] { return answer(Allow(), asked) },
		},
		{
			name:    "an error of the first rule fails the sign-in and the next rule is not asked",
			first:   fail,
			next:    func(asked *int) Policy[fakeTx] { return answer(Allow(), asked) },
			wantErr: true,
		},
		{
			name:          "an error of the next rule fails the sign-in",
			first:         func(asked *int) Policy[fakeTx] { return answer(Allow(), asked) },
			next:          fail,
			wantErr:       true,
			wantNextAsked: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var firstAsked, nextAsked int
			policy := tt.first(&firstAsked).Then(tt.next(&nextAsked))

			decision, err := policy(t.Context(), fakeTx{}, &sessioninfo.NewSessionRequest{})

			if (err != nil) != tt.wantErr {
				t.Fatalf("Then() error = %v, wantErr %v", err, tt.wantErr)
			}
			if firstAsked != 1 {
				t.Errorf("the first rule was asked %d times, want once", firstAsked)
			}
			if got := nextAsked == 1; got != tt.wantNextAsked {
				t.Errorf("the next rule was asked %d times, want asked %v", nextAsked, tt.wantNextAsked)
			}
			if diff := cmp.Diff(tt.wantDecision, decision, cmp.AllowUnexported(Decision{}), cmpopts.EquateErrors()); diff != "" {
				t.Errorf("decision mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTenantPolicy_Refused(t *testing.T) {
	t.Parallel()

	reader := &fakeDeclarations{}
	tests := []struct {
		name  string
		build func()
	}{
		{
			name:  "no role store",
			build: func() { TenantPolicy[fakeTx](nil, reader.read) },
		},
		{
			name:  "no declaration reader",
			build: func() { TenantPolicy[fakeTx](&fakeRoleManager{}, nil) },
		},
		{
			name:  "Then without a rule",
			build: func() { TenantPolicy(&fakeRoleManager{}, reader.read).Then(nil) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Error("want a panic: a wiring mistake is found at startup")
				}
			}()
			tt.build()
		})
	}
}
