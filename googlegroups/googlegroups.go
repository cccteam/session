//go:build !skipAuth

package googlegroups

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

// Directory looks up a user's direct Google Groups memberships through the Admin SDK
// Directory API. The service behind it is built on first use, not at construction.
type Directory struct {
	opts []option.ClientOption

	buildOnce sync.Once
	service   *admin.Service
	buildErr  error
}

// NewDirectory creates a Directory groups adapter.
//
// credentialsJSON is a service account key with domain-wide delegation granted for the
// https://www.googleapis.com/auth/admin.directory.group.readonly scope, and subject is
// the account the service account impersonates — an account holding a Groups-read admin
// privilege (a custom admin role with only Groups → Read is the least-privilege choice).
//
// credentialsJSON may be nil when opts carry the authentication instead (e.g. a token
// source, or an unauthenticated test endpoint); subject is then unused and may be empty.
//
// Construction is lazy. The inputs are validated here, but the Admin SDK service — and
// with it any credential resolution, including the fallback to Application Default
// Credentials when neither credentialsJSON nor opts authenticate — is built on the first
// UserGroups call. An application can therefore construct the adapter at startup in an
// environment without Google credentials; a credential problem surfaces from the first
// UserGroups, and from every later one.
func NewDirectory(ctx context.Context, credentialsJSON []byte, subject string, opts ...option.ClientOption) (*Directory, error) {
	if credentialsJSON != nil {
		if subject == "" {
			return nil, errors.New("subject is required with credentialsJSON: domain-wide delegation authorizes the service account only when impersonating an account with Groups-read privileges")
		}

		config, err := google.JWTConfigFromJSON(credentialsJSON, admin.AdminDirectoryGroupReadonlyScope)
		if err != nil {
			return nil, errors.Wrap(err, "google.JWTConfigFromJSON()")
		}
		config.Subject = subject

		opts = append([]option.ClientOption{option.WithTokenSource(config.TokenSource(ctx))}, opts...)
	}

	// The options outlive this call now, so the caller's slice is not the one kept.
	return &Directory{opts: slices.Clone(opts)}, nil
}

// UserGroups returns the email addresses of the groups the user is a direct member of,
// lowercased.
//
// The first call builds the Admin SDK service (see NewDirectory). When that fails —
// typically because no credentials could be resolved — the construction error is
// returned by this call and, unchanged, by every later one: the Directory does not
// retry, so a misconfigured adapter fails the same way on each login rather than
// re-resolving credentials every time.
func (d *Directory) UserGroups(ctx context.Context, email string) ([]string, error) {
	service, err := d.adminService(ctx)
	if err != nil {
		return nil, err
	}

	var groups []string
	err = service.Groups.List().UserKey(email).Pages(ctx, func(page *admin.Groups) error {
		for _, g := range page.Groups {
			groups = append(groups, strings.ToLower(g.Email))
		}

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "admin.GroupsListCall.Pages()")
	}

	return groups, nil
}

// adminService builds the Admin SDK service once and remembers the outcome, error
// included. The service is long-lived, so it is built under the first caller's context
// stripped of its cancellation: the request that happens to come first must not take
// the client down with it.
func (d *Directory) adminService(ctx context.Context) (*admin.Service, error) {
	d.buildOnce.Do(func() {
		service, err := admin.NewService(context.WithoutCancel(ctx), d.opts...)
		if err != nil {
			d.buildErr = errors.Wrap(err, "admin.NewService()")

			return
		}
		d.service = service
	})

	return d.service, d.buildErr
}
