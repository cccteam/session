package google

import "context"

// fakeGroups stands in for the Cloud Identity lookup: direct and nested name the groups
// each member gets from the lookup of that reach, err fails every lookup, and mode and
// token record the last call, so a test can see which lookup ran and with what.
type fakeGroups struct {
	direct, nested map[string][]string
	err            error
	mode           string
	token          string
}

func newFakeGroups() *fakeGroups {
	return &fakeGroups{direct: map[string][]string{}, nested: map[string][]string{}}
}

func (f *fakeGroups) DirectGroups(_ context.Context, token, member string) ([]string, error) {
	f.mode, f.token = lookupNameDirect, token

	return f.direct[member], f.err
}

func (f *fakeGroups) NestedGroups(_ context.Context, token, member string) ([]string, error) {
	f.mode, f.token = lookupNameNested, token

	return f.nested[member], f.err
}
