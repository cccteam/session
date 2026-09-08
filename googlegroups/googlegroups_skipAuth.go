//go:build skipAuth

package googlegroups

import (
	"context"
	"os"
	"strings"

	"google.golang.org/api/option"
)

// skipAuthGroupDomain is the domain the simulated groups are spelled under; the session
// package recognizes it under the same build tag and reads such a group as its role
// outright. A reserved name that resolves nowhere, so a simulated group can never be
// mistaken for a real one.
const skipAuthGroupDomain = "skipauth.invalid"

// Directory is the simulated directory under the skipAuth build tag: it answers a
// person's groups from APP_ROLES instead of the Admin SDK, the way the simulated login
// answers who they are from APP_USERNAME.
type Directory struct{}

// NewDirectory returns the simulated directory. Every argument is accepted and none is
// read: a development environment has no service account, and the application's
// construction code stays the same under both tags.
func NewDirectory(_ context.Context, _ []byte, _ string, _ ...option.ClientOption) (*Directory, error) {
	return &Directory{}, nil
}

// UserGroups returns one group per APP_ROLES entry (comma-separated), each spelled
// <role>@skipauth.invalid in lowercase; empty entries are ignored. Every simulated user is
// in the same groups, as every simulated login is APP_USERNAME.
func (*Directory) UserGroups(_ context.Context, _ string) ([]string, error) {
	var groups []string
	for _, role := range strings.Split(os.Getenv("APP_ROLES"), ",") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		groups = append(groups, strings.ToLower(role)+"@"+skipAuthGroupDomain)
	}

	return groups, nil
}
