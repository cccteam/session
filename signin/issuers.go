package signin

import "slices"

// Issuers is the set of issuers a registration's tokens may come from. A sign-in's
// provider session id is recorded under the issuer of the token that arrived
// (Verified.Issuer), since a provider's session id is unique only within its issuer,
// and a provider-initiated logout is scoped by the set: by the issuer the request
// names, when it names one, else by the set's only issuer, or by whichever of the set
// live sessions carry the id under (Entra sends the id alone). A registration serving
// one organization has one issuer; one serving listed organizations has several; one
// serving any organization has every well-formed issuer of its provider. A method
// without an issuer has none.
type Issuers interface {
	// Contains reports whether iss is one of the set. An empty string never is.
	Contains(iss string) bool
	// Only returns the set's single issuer when it has exactly one, which a logout
	// request that names no issuer is scoped by; a set with several has none, and such
	// a request is scoped by the issuers of the set live sessions carry the id under.
	Only() (string, bool)
}

// IssuerList returns the set of exactly the issuers listed, empty strings and
// repeats dropped.
func IssuerList(issuers ...string) Issuers {
	set := make(issuerList, 0, len(issuers))
	for _, iss := range issuers {
		if iss != "" && !slices.Contains(set, iss) {
			set = append(set, iss)
		}
	}

	return set
}

// issuerList is IssuerList's set.
type issuerList []string

// Contains reports whether iss is listed.
func (l issuerList) Contains(iss string) bool {
	return iss != "" && slices.Contains(l, iss)
}

// Only returns the one issuer of a single-issuer list.
func (l issuerList) Only() (string, bool) {
	if len(l) != 1 {
		return "", false
	}

	return l[0], true
}

// IssuersMatching returns the set of every issuer accept reports true for, such as
// every tenant issuer of a provider. It has no single issuer: a logout request naming
// none is scoped by the issuers of the set live sessions carry the id under.
func IssuersMatching(accept func(iss string) bool) Issuers {
	return issuersMatching(accept)
}

// issuersMatching is IssuersMatching's set.
type issuersMatching func(iss string) bool

// Contains reports whether the set's rule accepts iss.
func (m issuersMatching) Contains(iss string) bool {
	return iss != "" && m(iss)
}

// Only reports that a matching set has no single issuer.
func (issuersMatching) Only() (string, bool) {
	return "", false
}
