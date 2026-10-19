package google

import (
	"strings"

	"github.com/go-playground/errors/v5"
)

// AnyAccountConnection is the connection written on the link of a Google account that
// is in none of the registration's named Workspaces and is admitted by AnyGoogleAccount:
// the provider itself, since such an account belongs to no organization the
// application names. A Workspace account admitted by AnyWorkspace carries its domain.
const AnyAccountConnection = "accounts.google.com"

// anyWorkspaceAccount is the hd hint that asks Google's account chooser for any
// Workspace account, sent when a registration admits more than one domain.
const anyWorkspaceAccount = "*"

// WorkspaceSet is the organization slot of the Google method (Config.Workspaces): which
// Google accounts a registration admits, and the connection each identity link carries.
// It is built with Workspace, Workspaces, AnyWorkspace and AnyGoogleAccount; the zero
// value admits no one and is refused at registration. The verified ID token's hd claim,
// the domain of the account's Workspace, selects the entry: a named Workspace whose
// domains contain it, else any Workspace account when AnyWorkspace is in the set, else
// any account when AnyGoogleAccount is; an account no entry admits is refused
// (not_workspace_member).
type WorkspaceSet struct {
	named        []namedWorkspace
	anyWorkspace bool
	anyAccount   bool
}

// namedWorkspace is one Workspace the application names, with the domains it owns.
type namedWorkspace struct {
	name    string
	domains []string
}

// Workspace is one Google Workspace organization: name is the application's own name
// for it, written as the connection of every identity link made through it, and
// domains are the domains the Workspace owns, one or more, checked against the
// verified hd claim. Google puts no stable organization id in the token and one
// Workspace answers for every domain it owns, so the application names the Workspace
// rather than the library keying on a domain. The name is a key: changing it makes
// every sign-in from the Workspace arrive as an unknown identity until the links are
// re-keyed (see the README's "Google Workspace OIDC").
func Workspace(name string, domains ...string) WorkspaceSet {
	return WorkspaceSet{named: []namedWorkspace{{name: name, domains: domains}}}
}

// Workspaces combines sets: several named Workspaces, each with its own connection, or
// named Workspaces beside AnyWorkspace or AnyGoogleAccount, so the Workspaces the
// application knows carry their names and the rest fall through to the open entry. A
// domain belongs to one named Workspace only, and a name is used once.
func Workspaces(sets ...WorkspaceSet) WorkspaceSet {
	var union WorkspaceSet
	for _, s := range sets {
		union.named = append(union.named, s.named...)
		union.anyWorkspace = union.anyWorkspace || s.anyWorkspace
		union.anyAccount = union.anyAccount || s.anyAccount
	}

	return union
}

// AnyWorkspace admits an account of any Google Workspace organization: a token with any
// hd claim, none refused. The link's connection is the account's domain, lowercased,
// since the registration names no Workspace; a Workspace whose users should share one
// connection across its domains is named with Workspace beside this entry. Members of
// the directory is refused with it, since every Workspace in the world is "the
// directory": invited users only, open sign-up or a rule of the application's own
// decides a first sign-in.
func AnyWorkspace() WorkspaceSet {
	return WorkspaceSet{anyWorkspace: true}
}

// AnyGoogleAccount admits any Google account, in a Workspace or not: a token with or
// without an hd claim. The email must be verified, as always, since it is the sign-in
// name. The link's connection is AnyAccountConnection for an account outside the named
// Workspaces. The OAuth client's consent screen must be External and published for
// accounts outside your own Workspace to reach the callback; Internal restricts it to
// your Workspace. Members of the directory is refused with it, as with AnyWorkspace.
func AnyGoogleAccount() WorkspaceSet {
	return WorkspaceSet{anyAccount: true}
}

// validate is the slot's startup check: it refuses an empty slot, a Workspace without a
// name or a domain, a value that is not a domain name, a name used twice and a domain
// in two Workspaces, each naming the field.
func (s WorkspaceSet) validate() error {
	if len(s.named) == 0 && !s.anyWorkspace && !s.anyAccount {
		return errors.New("Workspaces is required: google.Workspace(name, domains...) for one Workspace, google.Workspaces(...) for several, " +
			"google.AnyWorkspace() for any Workspace account, google.AnyGoogleAccount() for any Google account")
	}
	names := map[string]bool{}
	domains := map[string]string{}
	for _, w := range s.named {
		if strings.TrimSpace(w.name) == "" {
			return errors.New("Workspaces: a Workspace needs a name, the application's own name for the organization, which keys every link made through it")
		}
		if names[strings.ToLower(w.name)] {
			return errors.Newf("Workspaces: the name %q is used twice", w.name)
		}
		names[strings.ToLower(w.name)] = true
		if len(w.domains) == 0 {
			return errors.Newf("Workspaces: Workspace %q needs at least one domain, checked against the verified hd claim", w.name)
		}
		for _, d := range w.domains {
			if !isDomainName(d) {
				return errors.Newf("Workspaces: %q is not a domain name", d)
			}
			key := strings.ToLower(d)
			if other, taken := domains[key]; taken {
				return errors.Newf("Workspaces: the domain %q belongs to two Workspaces, %q and %q", d, other, w.name)
			}
			domains[key] = w.name
		}
	}

	return nil
}

// isDomainName reports whether d can be a domain name an hd claim carries: not empty,
// and without spaces, control characters or the characters of a URL or an address.
func isDomainName(d string) bool {
	if d == "" || d != strings.TrimSpace(d) {
		return false
	}

	return !strings.ContainsFunc(d, func(c rune) bool { return c <= ' ' || c == 0x7f || strings.ContainsRune(`/@:*?#\`, c) })
}

// open reports whether the set admits accounts outside the named Workspaces: any
// Workspace account or any Google account.
func (s WorkspaceSet) open() bool {
	return s.anyWorkspace || s.anyAccount
}

// one returns the named Workspace when the set is exactly one and nothing else, which
// is the shape role synchronization reads groups of.
func (s WorkspaceSet) one() (namedWorkspace, bool) {
	if len(s.named) != 1 || s.open() {
		return namedWorkspace{}, false
	}

	return s.named[0], true
}

// connectionFor is the connection of a link made by an account whose verified hd claim
// is hd, and whether the set admits the account at all: the name of the Workspace whose
// domains contain hd, the lowercased domain under AnyWorkspace, AnyAccountConnection
// under AnyGoogleAccount. Domain names are compared without regard to case. An account
// outside a Workspace carries no hd claim and reaches AnyGoogleAccount only.
func (s WorkspaceSet) connectionFor(hd string) (string, bool) {
	if hd != "" {
		for _, w := range s.named {
			for _, d := range w.domains {
				if strings.EqualFold(hd, d) {
					return w.name, true
				}
			}
		}
		if s.anyWorkspace {
			return strings.ToLower(hd), true
		}
	}
	if s.anyAccount {
		return AnyAccountConnection, true
	}

	return "", false
}

// hdHint is the hd parameter of the authorization request, and whether one is sent: the
// domain itself when the set is one Workspace with one domain, so Google's chooser is
// narrowed to it; any Workspace account when the set admits several domains or any
// Workspace; none when any Google account is admitted. It is a hint only; the verifier
// enforces the claim.
func (s WorkspaceSet) hdHint() (string, bool) {
	if s.anyAccount {
		return "", false
	}
	if w, ok := s.one(); ok && len(w.domains) == 1 {
		return w.domains[0], true
	}

	return anyWorkspaceAccount, true
}

// simulatedHostedDomain is the hd claim the simulated sign-in asserts under the skipAuth
// build tag: the first domain of the first named Workspace, a reserved name under
// AnyWorkspace, and none under AnyGoogleAccount alone.
func (s WorkspaceSet) simulatedHostedDomain() string {
	if len(s.named) > 0 {
		return s.named[0].domains[0]
	}
	if s.anyWorkspace {
		return "skipauth.invalid"
	}

	return ""
}
