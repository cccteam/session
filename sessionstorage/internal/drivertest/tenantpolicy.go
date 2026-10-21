package drivertest

import (
	"context"
	"strings"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// The tenant policy on both backends, through the real sign-in flow: the person's
// memberships come from a role store, and each tenant's declaration is read by the
// application's reader in the sign-in's transaction, from the HookRecords table.

// roleStore stands in for the access library's user manager: the memberships each
// user holds. The tenant policy reads memberships and never writes them, so every
// write is an error.
type roleStore struct {
	held map[accesstypes.User]accesstypes.RoleCollection
}

func (s *roleStore) UserRoles(_ context.Context, user accesstypes.User, scopes ...accesstypes.PolicyScope) (accesstypes.RoleCollection, error) {
	if len(scopes) > 0 {
		return nil, errors.Newf("the tenant policy reads every membership the user holds, not %v", scopes)
	}

	return s.held[user], nil
}

func (s *roleStore) ResolveRole(context.Context, accesstypes.PolicyScope, string) (accesstypes.Role, bool, error) {
	return "", false, errors.New("the tenant policy never resolves a role")
}

func (s *roleStore) AddUserRoles(context.Context, accesstypes.PolicyScope, accesstypes.User, ...accesstypes.Role) error {
	return errors.New("the tenant policy never writes a membership")
}

func (s *roleStore) DeleteUserRoles(context.Context, accesstypes.PolicyScope, accesstypes.User, ...accesstypes.Role) error {
	return errors.New("the tenant policy never removes a membership")
}

// The HookRecords row a tenant's declaration is kept in: the key names the tenant, and
// the value lists its directories as method:connection and the directory-only mark,
// comma-separated.
const (
	declarationKeyPrefix = "tenant:"
	directoryOnlyMark    = "directory-only"
)

// declarationValue renders d as the value readDeclaration parses back.
func declarationValue(d *signin.TenantDeclaration) string {
	parts := make([]string, 0, len(d.Directories)+1)
	for _, directory := range d.Directories {
		parts = append(parts, string(directory.Method)+":"+directory.Connection)
	}
	if d.DirectoryOnly {
		parts = append(parts, directoryOnlyMark)
	}

	return strings.Join(parts, ",")
}

// readDeclaration is the application's reader of a tenant's declaration, over the
// hook's transaction: the row recorded under the tenant, parsed back, or nil when the
// tenant declares nothing.
func readDeclaration(ctx context.Context, tx HookTx, tenant accesstypes.Domain) (*signin.TenantDeclaration, error) {
	value, found, err := tx.Recorded(ctx, declarationKeyPrefix+string(tenant))
	if err != nil {
		return nil, errors.Wrap(err, "HookTx.Recorded()")
	}
	if !found {
		return nil, nil
	}

	d := &signin.TenantDeclaration{}
	for part := range strings.SplitSeq(value, ",") {
		if part == directoryOnlyMark {
			d.DirectoryOnly = true

			continue
		}
		method, connection, ok := strings.Cut(part, ":")
		if !ok {
			return nil, errors.Newf("declaration %q of tenant %q: %q is neither a directory nor the directory-only mark", value, tenant, part)
		}
		d.Directories = append(d.Directories, signin.Directory{Method: sessioninfo.AuthMethod(method), Connection: connection})
	}

	return d, nil
}

func testTenantPolicy(_ context.Context, t *testing.T, h *AuthHarness) {
	const jane = "jane@lakeside.edu"
	global := accesstypes.GlobalPolicyScope()
	lakesideScope := accesstypes.DomainPolicyScope("lakeside")
	riversideScope := accesstypes.DomainPolicyScope("riverside")
	member := []accesstypes.Role{"Member"}
	lakesideDirectory := signin.Directory{Method: sessioninfo.MethodWorkOS, Connection: "conn_lakeside"}
	riversideDirectory := signin.Directory{Method: sessioninfo.MethodWorkOS, Connection: "conn_riverside"}
	// chained is the application's own rule, chained after the tenant policy: it
	// records that it was asked and denies with its own code.
	chained := func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*signin.Decision, error) {
		if err := tx.Record(ctx, "chained:"+req.Username, "asked"); err != nil {
			return nil, errors.Wrap(err, "HookTx.Record()")
		}

		return signin.Deny("app_denied"), nil
	}

	tests := []struct {
		name string
		// held are jane's memberships, declared the tenants' declarations.
		held     accesstypes.RoleCollection
		declared map[accesstypes.Domain]*signin.TenantDeclaration
		// password signs jane in by password; otherwise through her Lakeside WorkOS
		// identity, linked beforehand.
		password bool
		opts     []signin.TenantPolicyOption
		// then is the application's own rule chained after the tenant policy, nil for
		// none.
		then func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*signin.Decision, error)
		// wantCode and wantCause are the refusal; none means the sign-in is allowed.
		wantCode  sessioninfo.LoginRefusalCode
		wantCause error
		// wantChained says whether the application's own rule was asked.
		wantChained bool
	}{
		{
			name: "a global role admits a sign-in through a directory no tenant declares",
			held: accesstypes.RoleCollection{global: {"Administrator"}},
		},
		{
			name:      "a member of no tenant is refused with no_tenant",
			wantCode:  sessioninfo.RefusedNoTenant,
			wantCause: signin.ErrNoTenant,
		},
		{
			name: "a member of no tenant is admitted with AdmitWithoutTenant",
			opts: []signin.TenantPolicyOption{signin.AdmitWithoutTenant()},
		},
		{
			name:     "a sign-in through a directory one of the person's tenants declares is admitted: the reader reads the declaration in the sign-in's transaction",
			held:     accesstypes.RoleCollection{lakesideScope: member, riversideScope: member},
			declared: map[accesstypes.Domain]*signin.TenantDeclaration{"riverside": {Directories: []signin.Directory{lakesideDirectory}}},
		},
		{
			name:      "a sign-in through a directory no tenant of the person declares is refused with connection_not_in_tenant",
			held:      accesstypes.RoleCollection{lakesideScope: member, riversideScope: member},
			declared:  map[accesstypes.Domain]*signin.TenantDeclaration{"lakeside": {Directories: []signin.Directory{riversideDirectory}}},
			wantCode:  sessioninfo.RefusedConnectionNotInTenant,
			wantCause: signin.ErrConnectionNotInTenant,
		},
		{
			name:     "a password is admitted when one of the person's tenants admits its people other than through its directory",
			held:     accesstypes.RoleCollection{lakesideScope: member, riversideScope: member},
			declared: map[accesstypes.Domain]*signin.TenantDeclaration{"lakeside": {Directories: []signin.Directory{lakesideDirectory}, DirectoryOnly: true}},
			password: true,
		},
		{
			name: "a password is refused with directory_only when every tenant of the person is directory only",
			held: accesstypes.RoleCollection{lakesideScope: member, riversideScope: member},
			declared: map[accesstypes.Domain]*signin.TenantDeclaration{
				"lakeside":  {Directories: []signin.Directory{lakesideDirectory}, DirectoryOnly: true},
				"riverside": {DirectoryOnly: true},
			},
			password:  true,
			wantCode:  sessioninfo.RefusedDirectoryOnly,
			wantCause: signin.ErrDirectoryOnly,
		},
		{
			name:        "the application's own rule is asked after the tenant policy allows, and its answer is the decision",
			held:        accesstypes.RoleCollection{lakesideScope: member},
			declared:    map[accesstypes.Domain]*signin.TenantDeclaration{"lakeside": {Directories: []signin.Directory{lakesideDirectory}}},
			then:        chained,
			wantCode:    "app_denied",
			wantCause:   signin.ErrSignInDenied,
			wantChained: true,
		},
		{
			name:      "the application's own rule is not asked after the tenant policy denies",
			then:      chained,
			wantCode:  sessioninfo.RefusedNoTenant,
			wantCause: signin.ErrNoTenant,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			policy := signin.TenantPolicy(&roleStore{held: map[accesstypes.User]accesstypes.RoleCollection{jane: tt.held}}, readDeclaration, tt.opts...)
			if tt.then != nil {
				policy = policy.Then(tt.then)
			}
			in := h.New(ctx, t, AuthWithAppTables, AuthConfig{Auth: true, Policy: policy})
			for tenant, declaration := range tt.declared {
				h.Record(ctx, t, in.Raw, declarationKeyPrefix+string(tenant), declarationValue(declaration))
			}
			user := passwordUser(ctx, t, in.Driver, jane)

			var err error
			if tt.password {
				_, err = passwordSignIn(ctx, in, user, sessioninfo.ReasonLogin)
			} else {
				mustLink(ctx, t, in.Driver, user.ID, lakeside("idp_jane"))
				_, _, err = signIn(ctx, in, lakeside("idp_jane"), sessioninfo.ReasonLogin)
			}

			if tt.wantCode == "" {
				if err != nil {
					t.Errorf("sign-in error = %v (code %q), want allowed", err, sessioninfo.LoginRefusalCodeOf(err))
				}
			} else {
				assertRefused(t, err, tt.wantCode, tt.wantCause)
				if !errors.Is(err, signin.ErrSignInDenied) {
					t.Errorf("sign-in error = %v, want ErrSignInDenied in the chain too", err)
				}
			}
			if _, asked := h.Recorded(ctx, t, in.Raw, "chained:"+jane); asked != tt.wantChained {
				t.Errorf("the application's own rule asked = %v, want %v", asked, tt.wantChained)
			}
		})
	}
}
