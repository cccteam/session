package access

import (
	"fmt"
	"strings"
)

// GlobalDomain is the domain used when a permission is applied at the Global level
// instead of to a specific domain.
const GlobalDomain = Domain("global")

const domainPrefix = "domain:"

type Domain string

func unmarshalDomain(domain string) Domain {
	return Domain(strings.TrimPrefix(domain, domainPrefix))
}

func (d Domain) Marshal() string {
	if !d.IsValid() {
		panic(fmt.Sprintf("invalid domain %q, type can not contain prefix", string(d)))
	}

	return domainPrefix + string(d)
}

func (d Domain) IsValid() bool {
	return !strings.HasPrefix(string(d), domainPrefix)
}