package google

import "strings"

// anyWorkspaceAccount is the hd hint that asks Google's account chooser for any
// Workspace account, sent when a registration spans several hosted domains.
const anyWorkspaceAccount = "*"

// hostedDomainHint is the hd parameter of the authorization request for hostedDomains:
// the domain itself when there is one, so Google's chooser is narrowed to it, and any
// Workspace account when there are several. It is a hint only; Verify enforces the
// claim.
func hostedDomainHint(hostedDomains []string) string {
	if len(hostedDomains) == 1 {
		return hostedDomains[0]
	}

	return anyWorkspaceAccount
}

// allowsHostedDomain reports whether hd, the verified token's hosted-domain claim, is one
// of hostedDomains. Domain names are case-insensitive. An empty claim (a consumer
// account) is never allowed.
func allowsHostedDomain(hostedDomains []string, hd string) bool {
	if hd == "" {
		return false
	}
	for _, domain := range hostedDomains {
		if strings.EqualFold(hd, domain) {
			return true
		}
	}

	return false
}

// primaryHostedDomain is the first of hostedDomains, or "" when there are none: the
// domain the simulated sign-in asserts.
func primaryHostedDomain(hostedDomains []string) string {
	if len(hostedDomains) == 0 {
		return ""
	}

	return hostedDomains[0]
}
