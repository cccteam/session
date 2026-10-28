package azure

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// DefaultAuthority is the Microsoft identity platform the tenants of the public cloud
// live on. Config.Authority takes it when empty; Azure Government tenants live at
// https://login.microsoftonline.us.
const DefaultAuthority = "https://login.microsoftonline.com"

// ConsumerTenantID is the tenant id of Microsoft personal accounts (outlook.com,
// hotmail.com, Xbox): the tid claim every personal account's token carries. It is
// admitted only by PersonalAccounts, and refused as a listed tenant.
const ConsumerTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

// The shared endpoints of the Microsoft identity platform, whose discovery documents
// name their issuer with a placeholder.
const (
	endpointOrganizations = "organizations"
	endpointCommon        = "common"
	endpointConsumers     = "consumers"
)

// personalDomains are the domains of Microsoft personal accounts, the consumer
// tenant's, which only PersonalAccounts admits.
var personalDomains = []string{"outlook.com", "hotmail.com", "live.com", "msn.com"}

// tenantIDPattern is the shape of a tenant id: a GUID.
var tenantIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// TenantSet is the organization slot of the Entra method (Config.Tenants): which
// Microsoft Entra tenants' accounts a registration admits. It is built with Tenant,
// NamedTenant, Tenants, AnyTenant and PersonalAccounts; the zero value admits no one
// and is refused at registration. The verified ID token's tid claim selects the entry
// at the callback, before the account rules run: a listed tenant, any work or school
// tenant under AnyTenant, Microsoft's consumer tenant under PersonalAccounts; a token
// from a tenant the slot does not admit is refused (unlisted_tenant, or
// personal_account for a personal account). The identity key stays (tid, oid) under
// every shape.
type TenantSet struct {
	listed   []namedTenant
	any      bool
	personal bool
	// attestsOpen records Attesting() called on a set with an open entry, which
	// validate refuses: an open entry admits tenants the application does not
	// administer.
	attestsOpen bool
}

// namedTenant is one tenant the application lists, with the name it gives it, "" for
// none, and whether the application declares it as enforcing a second factor.
type namedTenant struct {
	id      string
	name    string
	attests bool
}

// Tenant is one Microsoft Entra tenant, by its tenant id (the tid claim, a GUID): the
// application that belongs to one organization, as a single-tenant app registration
// serves it. The tenant id is the tenant key the standard account rules store on the
// links made through it.
func Tenant(id string) TenantSet {
	return TenantSet{listed: []namedTenant{{id: id}}}
}

// NamedTenant is Tenant with the application's own name for the tenant, which the
// standard account rules store as the tenant key of the links made through it in place
// of the tenant id. The identity key is still (tid, oid).
func NamedTenant(id, name string) TenantSet {
	return TenantSet{listed: []namedTenant{{id: id, name: name}}}
}

// Tenants combines sets: several listed tenants, each admitted by its id, or listed
// tenants beside AnyTenant or PersonalAccounts. A tenant id is listed once and a name
// is used once. Several tenants are served through Microsoft's shared endpoint, so
// the app registration must admit accounts in any organizational directory, and the
// token's issuer is checked against its tenant by this library.
func Tenants(sets ...TenantSet) TenantSet {
	var union TenantSet
	for _, s := range sets {
		union.listed = append(union.listed, s.listed...)
		union.any = union.any || s.any
		union.personal = union.personal || s.personal
		union.attestsOpen = union.attestsOpen || s.attestsOpen
	}

	return union
}

// Attesting declares that the tenants listed in the set enforce a second factor at
// every sign-in, which the application vouches for because it administers them (a
// Conditional Access policy requiring multifactor authentication for every user): a
// sign-in through one of them carries the attestation by declaration
// (sessioninfo.AttestedByDeclaration), recorded as the session's
// attested-by-declaration event, which satisfies the sign-in policy's RequireMFA
// without a code. A token whose amr claim names mfa attests by evidence under every
// shape, declared or not, since Entra asserts it only after its own multifactor
// authentication; the declaration covers the sign-ins Entra admits under a policy that
// asks for no second factor it would name. It is for listed tenants only: AnyTenant
// and PersonalAccounts admit tenants the application does not administer, and a set
// holding either is refused at registration; list the administered tenant beside the
// open entry instead.
func (s TenantSet) Attesting() TenantSet {
	listed := make([]namedTenant, len(s.listed))
	for i, t := range s.listed {
		listed[i] = namedTenant{id: t.id, name: t.name, attests: true}
	}

	return TenantSet{listed: listed, any: s.any, personal: s.personal, attestsOpen: s.attestsOpen || s.open()}
}

// AnyTenant admits the work or school account of any Microsoft Entra tenant, and no
// personal account. Members of the directory is refused with it, since every tenant in
// the world is "the directory": invited users only, open sign-up or a rule of the
// application's own decides a first sign-in. Role synchronization is refused with it,
// since a token's application roles are asserted by the tenant that issued it.
func AnyTenant() TenantSet {
	return TenantSet{any: true}
}

// PersonalAccounts admits Microsoft personal accounts (ConsumerTenantID): the
// consumer tenant, which a work or school shape never admits. Beside AnyTenant or
// listed tenants it is served through Microsoft's common endpoint; alone, through the
// consumers endpoint. Members of the directory and role synchronization are refused
// with it, as with AnyTenant.
func PersonalAccounts() TenantSet {
	return TenantSet{personal: true}
}

// validate is the slot's startup check: it refuses an empty slot, a tenant id that is
// not a GUID, the consumer tenant listed as a tenant, a tenant listed twice and a name
// used twice, each naming the field.
func (s TenantSet) validate() error {
	if len(s.listed) == 0 && !s.any && !s.personal {
		return errors.New("Tenants is required: azure.Tenant(id) for one tenant, azure.Tenants(...) for several, " +
			"azure.AnyTenant() for any work or school account, azure.PersonalAccounts() for Microsoft personal accounts")
	}
	if s.attestsOpen {
		return errors.New("Tenants: Attesting() declares the tenants the application administers; any tenant and personal accounts admit tenants it does not, " +
			"so list the administered tenant beside the open entry: azure.Tenants(azure.Tenant(id).Attesting(), azure.AnyTenant())")
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, t := range s.listed {
		if !tenantIDPattern.MatchString(t.id) {
			return errors.Newf("Tenants: %q is not a tenant id (a GUID, the tid claim)", t.id)
		}
		id := strings.ToLower(t.id)
		if id == ConsumerTenantID {
			return errors.Newf("Tenants: %q is Microsoft's consumer tenant, the personal accounts: use azure.PersonalAccounts()", t.id)
		}
		if ids[id] {
			return errors.Newf("Tenants: the tenant %q is listed twice", t.id)
		}
		ids[id] = true
		if t.name != "" {
			if strings.TrimSpace(t.name) == "" {
				return errors.Newf("Tenants: the name of tenant %q is blank", t.id)
			}
			if names[strings.ToLower(t.name)] {
				return errors.Newf("Tenants: the name %q is used twice", t.name)
			}
			names[strings.ToLower(t.name)] = true
		}
	}

	return nil
}

// open reports whether the set admits accounts outside the listed tenants: any tenant
// or personal accounts.
func (s TenantSet) open() bool {
	return s.any || s.personal
}

// one returns the listed tenant when the set is exactly one and nothing else, which is
// the shape served at the tenant's own endpoint and the only one role synchronization
// follows.
func (s TenantSet) one() (namedTenant, bool) {
	if len(s.listed) != 1 || s.open() {
		return namedTenant{}, false
	}

	return s.listed[0], true
}

// admits reports whether the set admits a token of tenant tid, and the organization
// the standard account rules store as the tenant key: the tenant's name when the
// application gave one, the tenant id in lower case otherwise, and "" when the tenant
// is not admitted. Tenant ids are compared without regard to case.
func (s TenantSet) admits(tid string) (organization string, ok bool) {
	if tid == "" {
		return "", false
	}
	for _, t := range s.listed {
		if strings.EqualFold(t.id, tid) {
			if t.name != "" {
				return t.name, true
			}

			return strings.ToLower(tid), true
		}
	}
	switch {
	case strings.EqualFold(tid, ConsumerTenantID) && s.personal, !strings.EqualFold(tid, ConsumerTenantID) && s.any:
		return strings.ToLower(tid), true
	default:
		return "", false
	}
}

// attests reports whether the set declares tenant tid as enforcing a second factor
// (Attesting()): a listed tenant so declared. An open entry never attests.
func (s TenantSet) attests(tid string) bool {
	for _, t := range s.listed {
		if strings.EqualFold(t.id, tid) {
			return t.attests
		}
	}

	return false
}

// admitsAddress reports whether the set could admit an account whose email address is
// at domain, which the core asks before it sends an invitation there. A tenant is not
// a domain, so the only address the set can judge is a personal account's, refused
// unless the set admits personal accounts; every other address is admitted, since the
// domains of a tenant's accounts are not known here.
func (s TenantSet) admitsAddress(domain string) bool {
	return s.personal || !slices.ContainsFunc(personalDomains, func(d string) bool { return strings.EqualFold(d, domain) })
}

// refusal is the refusal of a token of tenant tid the set does not admit: a personal
// account under a work or school shape (personal_account), or a tenant outside the
// listed ones (unlisted_tenant).
func (s TenantSet) refusal(tid string) error {
	if strings.EqualFold(tid, ConsumerTenantID) {
		return sessioninfo.NewLoginRefusal(sessioninfo.RefusedPersonalAccount, httpio.NewForbiddenMessage("Personal Microsoft accounts cannot sign in here"))
	}

	return sessioninfo.NewLoginRefusal(sessioninfo.RefusedUnlistedTenant, httpio.NewForbiddenMessagef("The organization %s cannot sign in here", tid))
}

// discoveryURL is where the registration's provider configuration is read from under
// authority: the tenant's own endpoint for one tenant, whose document names the
// tenant's issuer; otherwise a shared endpoint, whose document names its issuer with
// a placeholder: organizations for work or school accounts, consumers for personal
// accounts alone, common for both.
func (s TenantSet) discoveryURL(authority string) string {
	if t, ok := s.one(); ok {
		return issuerOf(authority, t.id)
	}
	switch {
	case s.personal && (s.any || len(s.listed) > 0):
		return authority + "/" + endpointCommon + "/v2.0"
	case s.personal:
		return authority + "/" + endpointConsumers + "/v2.0"
	default:
		return authority + "/" + endpointOrganizations + "/v2.0"
	}
}

// shared reports whether the registration is served through a shared endpoint, whose
// discovery document cannot be held to its issuer: the token's issuer is then checked
// against the token's tenant by this library.
func (s TenantSet) shared() bool {
	_, one := s.one()

	return !one
}

// issuers is the set of issuers the registration's tokens may come from, for the
// core: the one tenant's issuer, or every issuer under authority of a tenant the set
// admits.
func (s TenantSet) issuers(authority string) signin.Issuers {
	if t, ok := s.one(); ok {
		return signin.IssuerList(issuerOf(authority, t.id))
	}

	return signin.IssuersMatching(func(iss string) bool {
		tid, ok := tenantOfIssuer(authority, iss)
		if !ok {
			return false
		}
		_, admitted := s.admits(tid)

		return admitted
	})
}

// simulatedTenantID is the tenant the simulated sign-in asserts under the skipAuth
// build tag, one the set admits: the first listed tenant, the consumer tenant when the
// set admits personal accounts only, and fallback under any tenant.
func (s TenantSet) simulatedTenantID(fallback string) string {
	switch {
	case len(s.listed) > 0:
		return strings.ToLower(s.listed[0].id)
	case s.personal && !s.any:
		return ConsumerTenantID
	default:
		return fallback
	}
}

// issuerOf is the issuer of tenant tid's v2.0 tokens under authority.
func issuerOf(authority, tid string) string {
	return authority + "/" + strings.ToLower(tid) + "/v2.0"
}

// TenantOfIssuer reads a tenant's v2.0 issuer, <authority>/<tenant id>/v2.0, into the
// authority and the tenant it names, for a configuration that holds the issuer of one
// tenant as v0.12 did (Config.Authority and Config.Tenants hold them apart). An issuer
// of another shape is an error.
func TenantOfIssuer(issuerURL string) (authority string, tenant TenantSet, err error) {
	base, ok := strings.CutSuffix(strings.TrimSuffix(issuerURL, "/"), "/v2.0")
	i := strings.LastIndex(base, "/")
	if !ok || i <= 0 || !tenantIDPattern.MatchString(base[i+1:]) {
		return "", TenantSet{}, errors.Newf("%q is not the issuer of a Microsoft Entra tenant, <authority>/<tenant id>/v2.0", issuerURL)
	}
	authority, err = authorityOf(base[:i])
	if err != nil {
		return "", TenantSet{}, errors.Wrap(err, "azure.authorityOf()")
	}

	return authority, Tenant(base[i+1:]), nil
}

// tenantOfIssuer reads the tenant id out of an issuer under authority, and reports
// whether iss has that shape: authority, one tenant id segment, v2.0.
func tenantOfIssuer(authority, iss string) (string, bool) {
	rest, ok := strings.CutPrefix(iss, authority+"/")
	if !ok {
		return "", false
	}
	tid, ok := strings.CutSuffix(rest, "/v2.0")
	if !ok || !tenantIDPattern.MatchString(tid) {
		return "", false
	}

	return tid, true
}

// authorityOf validates and normalizes Config.Authority: the default when empty,
// otherwise an http or https URL with a host and nothing after it, without a trailing
// slash.
func authorityOf(authority string) (string, error) {
	if authority == "" {
		return DefaultAuthority, nil
	}
	u, err := url.Parse(authority)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return "", errors.Newf("Authority: %q is not the base URL of a Microsoft identity platform, such as %s", authority, DefaultAuthority)
	}

	return strings.TrimSuffix(authority, "/"), nil
}
