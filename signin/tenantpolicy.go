package signin

import (
	"context"
	"slices"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// Directory is a directory a tenant admits its people through: a sign-in method and
// the connection its identities carry, the values of Identity.Method and
// Identity.Connection, which the session's first auth event records too. A Microsoft
// Entra tenant is named by its tenant id under MethodAzure, a Google Workspace by the
// name the registration gives it under MethodGoogle, a WorkOS connection by its id
// under MethodWorkOS.
type Directory struct {
	Method     sessioninfo.AuthMethod
	Connection string
}

// DeclaredDirectory is one tenant's declaration of a directory, as a DirectoryReader
// answers it for a stranger's first sign-in: the tenant, and the default seat the
// tenant gives a person its directory vouched for, the role the sign-in seats them
// with in the tenant, or "" when the tenant admits its people by invitation only.
type DeclaredDirectory struct {
	Tenant      accesstypes.Domain
	DefaultSeat accesstypes.Role
}

// DirectoryReader reads every tenant's declaration of a directory for a stranger's
// first sign-in, in the sign-in's first transaction, typed to the storage's
// transaction like the other hooks: the tenants that declare the directory the
// identity came through, each with its default seat. A directory some tenant declares
// belongs to that tenant, and its declaration decides the stranger before the
// registration's account rule does; a directory no tenant declares, an empty answer,
// falls to the registration's rule as it would without the reader. Spanner may retry
// the transaction, so the reader must not have side effects outside it. Set it on
// the Auth with SetDirectoryAdmission, beside the hook that seats the person.
type DirectoryReader[Tx any] func(ctx context.Context, tx Tx, directory Directory) ([]DeclaredDirectory, error)

// DirectorySeat is a seat a first sign-in grants: a role in a tenant, the default seat
// of a directory the tenant declared, written by the application's hook once the
// user is committed.
type DirectorySeat struct {
	Tenant accesstypes.Domain
	Role   accesstypes.Role
}

// TenantDeclaration is what a tenant declares about who may enter it: the directories
// its people come through, and whether they come through those only. It is
// configuration data of the tenant, kept by the application and read for the library
// by a DeclarationReader. A tenant that declares nothing, a nil or an empty
// declaration, admits its people by password and through no directory.
type TenantDeclaration struct {
	// Directories are the directories the tenant admits its people through. One
	// tenant has one directory as a rule; a second one is an explicit second
	// declaration.
	Directories []Directory
	// DirectoryOnly says the tenant's people enter through its directories only: a
	// password, or any other sign-in that is not through a directory, does not reach
	// the tenant.
	DirectoryOnly bool
}

// Admits reports whether the declaration admits a session established through method
// and connection, as the session's first auth event records them
// (sessioninfo.SessionData.EstablishedBy): a sign-in through a directory
// (sessioninfo.AuthMethod.ThroughDirectory) when (method, connection) is one of the
// declared directories; any other establishment, a password or a step the
// application recorded under its own name, unless the tenant is directory only. The
// tenant policy decides with it at sign-in, over every tenant of the person, and the
// application decides with it again when the session reaches one tenant, where the
// session's tenant list is computed. It reads nothing: a nil declaration declares
// nothing.
func (d *TenantDeclaration) Admits(method sessioninfo.AuthMethod, connection string) bool {
	if method.ThroughDirectory() {
		return d.declares(Directory{Method: method, Connection: connection})
	}

	return d == nil || !d.DirectoryOnly
}

// declares reports whether directory is one of the declared directories.
func (d *TenantDeclaration) declares(directory Directory) bool {
	return d != nil && slices.Contains(d.Directories, directory)
}

// DeclarationReader reads a tenant's declaration for the tenant policy, in the
// sign-in's transaction, typed to the storage's transaction like the other hooks
// (pgx.Tx on PostgreSQL, *spanner.ReadWriteTransaction on Spanner). It answers nil for
// a tenant that declares nothing. Spanner may retry the transaction, so the reader
// must not have side effects outside it.
type DeclarationReader[Tx any] func(ctx context.Context, tx Tx, tenant accesstypes.Domain) (*TenantDeclaration, error)

// TenantPolicyOption refines the tenant policy.
type TenantPolicyOption func(settings *tenantPolicySettings)

// tenantPolicySettings are the tenant policy's options.
type tenantPolicySettings struct {
	admitWithoutTenant bool
}

// AdmitWithoutTenant admits a person who is a member of no tenant instead of refusing
// them (no_tenant). The self-service shape of an application needs it: a stranger
// signs in, then creates their organization, whose first membership the application
// writes; until then the session reaches no tenant.
func AdmitWithoutTenant() TenantPolicyOption {
	return func(settings *tenantPolicySettings) {
		settings.admitWithoutTenant = true
	}
}

// tenantPolicy is the tenant policy's state: the role store the memberships are read
// from, the reader of a tenant's declaration, and the options.
type tenantPolicy[Tx any] struct {
	roles        UserRoleManager
	declarations DeclarationReader[Tx]
	settings     tenantPolicySettings
}

// TenantPolicy is the library's sign-in rule for an application whose users belong to
// tenants: a person signs in when one of their tenants admits the way they signed in.
// The person's tenants are the domains where they hold a role, read through roles, the
// access library's user manager, and what each tenant admits is its declaration
// (TenantDeclaration), read through declarations in the sign-in's transaction. The
// policy decides what the session may be; which of the person's tenants the session
// then reaches is decided again, tenant by tenant, where the session's tenant list is
// computed, with TenantDeclaration.Admits over the session's first auth event. It
// never writes. Set it with session.Auth.SetSignInPolicy; Then chains the
// application's own rule after it.
//
// The rules, in order, once the user is known:
//
//  1. A person holding a role in the global partition or in every tenant domain is the
//     application's own staff and is admitted on the library's own checks, as is a
//     sign-in whose method synchronizes roles (the directory names the person's roles,
//     and the synchronization, which runs once the session stands, refuses a person
//     with none); the application's own directories are admitted by the registration's
//     organization slot already.
//  2. A person who is a member of no tenant is refused (no_tenant), unless the policy
//     was built with AdmitWithoutTenant.
//  3. A sign-in through a directory (Entra, Google, WorkOS) is admitted when one of the
//     person's tenants declares the directory it came through, its (method,
//     connection), and refused otherwise (connection_not_in_tenant).
//  4. Any other sign-in, a password or a session the application starts for a user it
//     authenticated itself, is admitted when one of the person's tenants admits its
//     people other than through its directories, and refused when every one of them is
//     directory only (directory_only).
//
// A refusal is a sessioninfo.LoginRefusal with its code, and errors.Is matches
// ErrSignInDenied and the rule's own cause (ErrNoTenant, ErrConnectionNotInTenant,
// ErrDirectoryOnly). A role store or reader error fails the sign-in (internal_error).
// A nil roles or declarations is a wiring mistake and panics.
//
// A stranger, a person no user was created for, never reaches the policy as such: the
// account rules decide them first, and in a tenanted application the tenants'
// declarations decide before the registration's rule, through the directory reader
// and seat hook set with session.Auth.SetDirectoryAdmission (DirectoryReader): a
// default seat admits and seats the person, so the policy then finds the membership,
// and a declaration without one refuses them by invitation only.
func TenantPolicy[Tx any](roles UserRoleManager, declarations DeclarationReader[Tx], opts ...TenantPolicyOption) Policy[Tx] {
	if roles == nil {
		panic("signin: TenantPolicy was given no role store: pass the access library's user manager")
	}
	if declarations == nil {
		panic("signin: TenantPolicy was given no declaration reader: pass the application's reader of a tenant's declaration")
	}
	p := &tenantPolicy[Tx]{roles: roles, declarations: declarations}
	for _, opt := range opts {
		opt(&p.settings)
	}

	return p.decide
}

// decide is the policy: see TenantPolicy for the rules.
func (p *tenantPolicy[Tx]) decide(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*Decision, error) {
	if req.RoleNames != nil {
		return Allow(), nil
	}
	held, err := p.roles.UserRoles(ctx, accesstypes.User(req.Username))
	if err != nil {
		return nil, errors.Wrap(err, "UserRoleManager.UserRoles()")
	}
	staff, tenants := membership(held)
	if staff {
		return Allow(), nil
	}
	if len(tenants) == 0 {
		if p.settings.admitWithoutTenant {
			return Allow(), nil
		}

		return denyBecause(sessioninfo.RefusedNoTenant, ErrNoTenant), nil
	}

	method, connection := establishment(req)
	for _, tenant := range tenants {
		declaration, err := p.declarations(ctx, tx, tenant)
		if err != nil {
			return nil, errors.Wrapf(err, "DeclarationReader(%q)", tenant)
		}
		if declaration.Admits(method, connection) {
			return Allow(), nil
		}
	}
	if method.ThroughDirectory() {
		return denyBecause(sessioninfo.RefusedConnectionNotInTenant, ErrConnectionNotInTenant), nil
	}

	return denyBecause(sessioninfo.RefusedDirectoryOnly, ErrDirectoryOnly), nil
}

// membership reads the person's memberships: staff when a role is held in the global
// partition or in every tenant domain, and the tenants where a role is held, in a
// fixed order, so the declarations are read the same way at every sign-in.
func membership(held accesstypes.RoleCollection) (staff bool, tenants []accesstypes.Domain) {
	for scope, roles := range held {
		if len(roles) == 0 {
			continue
		}
		if scope.IsGlobal() || scope.IsEveryDomain() {
			staff = true

			continue
		}
		if domain, ok := scope.Domain(); ok && domain != "" {
			tenants = append(tenants, domain)
		}
	}
	slices.Sort(tenants)

	return staff, tenants
}

// establishment is how the sign-in proves who the person is: the identity's method
// and connection, which the session's first auth event will record.
func establishment(req *sessioninfo.NewSessionRequest) (method sessioninfo.AuthMethod, connection string) {
	if req.Identity == nil {
		return "", ""
	}

	return req.Identity.Method, req.Identity.Connection
}
