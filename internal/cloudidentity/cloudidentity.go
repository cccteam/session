// Package cloudidentity reads the Google Groups a person belongs to through the Cloud
// Identity Groups API, with the person's own access token. Google answers only the
// groups whose member list the person may view and leaves the rest out, so no
// administrator credential and no delegation are involved: one hidden group costs
// that one membership, never the lookup.
package cloudidentity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/option"
)

const (
	// Scope is the OAuth scope the person's token needs for the lookup.
	Scope = cloudidentity.CloudIdentityGroupsReadonlyScope

	// MaxDepth is how many levels of nesting NestedGroups follows: the person's own groups
	// are the first level, the groups those groups are in the second, and so on.
	MaxDepth = 10

	// pageSize is the largest page the API serves. A person can be in about 3,600 groups
	// directly, so a lookup may still need more than one page, and every page is read.
	pageSize = 1000

	// atOnce is how many groups' parents are asked for at the same time on one level.
	// Each level's calls are independent; the next level cannot start until the whole
	// level has answered, so depth, not width, is what makes the nested lookup slow.
	atOnce = 8
)

// Lookup reads groups through the Cloud Identity Groups API. The zero value talks to
// Google; Endpoint points a test at a fake server.
type Lookup struct {
	// Endpoint, when set, replaces the API's base URL.
	Endpoint string
}

// DirectGroups returns the email addresses, lowercased and sorted, of the groups member
// is directly in and may view. token is the person's own access token, carrying Scope.
func (l Lookup) DirectGroups(ctx context.Context, token, member string) ([]string, error) {
	service, err := l.service(ctx, token)
	if err != nil {
		return nil, err
	}
	groups, err := directGroups(ctx, service, member)
	if err != nil {
		return nil, err
	}
	sort.Strings(groups)

	return groups, nil
}

// NestedGroups returns the email addresses, lowercased and sorted, of the groups member
// is in directly or through nesting, up to MaxDepth levels. Each level asks for the
// parents of the groups the previous level found, several at a time; a group already
// seen is not asked about again, so a cycle ends the climb rather than looping. A group
// the person may not view never appears, so nothing above it is reached.
func (l Lookup) NestedGroups(ctx context.Context, token, member string) ([]string, error) {
	service, err := l.service(ctx, token)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	level := []string{member}
	for depth := 0; depth < MaxDepth && len(level) > 0; depth++ {
		parents := make([][]string, len(level))
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(atOnce)
		for i, m := range level {
			g.Go(func() error {
				groups, err := directGroups(gctx, service, m)
				if err != nil {
					return err
				}
				parents[i] = groups

				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return nil, errors.Wrap(err, "errgroup.Group.Wait()")
		}
		var next []string
		for _, groups := range parents {
			for _, group := range groups {
				if !seen[group] {
					seen[group] = true
					next = append(next, group)
				}
			}
		}
		level = next
	}
	all := make([]string, 0, len(seen))
	for group := range seen {
		all = append(all, group)
	}
	sort.Strings(all)

	return all, nil
}

// service builds a client that sends the person's token. Building one is cheap: no
// request is made until a lookup runs.
func (l Lookup) service(ctx context.Context, token string) (*cloudidentity.Service, error) {
	if token == "" {
		return nil, errors.New("the group lookup needs the person's access token, and none was given")
	}
	opts := []option.ClientOption{option.WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))}
	if l.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(l.Endpoint))
	}
	service, err := cloudidentity.NewService(ctx, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "cloudidentity.NewService()")
	}

	return service, nil
}

// directGroups asks for the groups member is directly in, following every page. The
// query names the member alone: Google's reference asks for a label clause as well, but
// the API refuses one, and the member-only query answers with every group the person
// may view (checked 2026-09-30).
func directGroups(ctx context.Context, service *cloudidentity.Service, member string) ([]string, error) {
	if strings.ContainsAny(member, `'\`) {
		return nil, errors.Newf("member %q cannot be looked up: a quote or a backslash would change the query", member)
	}
	var groups []string
	call := service.Groups.Memberships.SearchDirectGroups("groups/-").Query(fmt.Sprintf("member_key_id == '%s'", member)).PageSize(pageSize)
	err := call.Pages(ctx, func(page *cloudidentity.SearchDirectGroupsResponse) error {
		for _, m := range page.Memberships {
			if m.GroupKey != nil && m.GroupKey.Id != "" {
				groups = append(groups, strings.ToLower(m.GroupKey.Id))
			}
		}

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "cloudidentity.GroupsMembershipsSearchDirectGroupsCall.Pages()")
	}

	return groups, nil
}
