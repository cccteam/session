//go:build !skipAuth

package googlegroups

import (
	"context"
	"strings"

	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

// Directory looks up a user's direct Google Groups memberships through the Admin SDK
// Directory API.
type Directory struct {
	service *admin.Service
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

	service, err := admin.NewService(ctx, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "admin.NewService()")
	}

	return &Directory{service: service}, nil
}

// UserGroups returns the email addresses of the groups the user is a direct member of,
// lowercased.
func (d *Directory) UserGroups(ctx context.Context, email string) ([]string, error) {
	var groups []string
	err := d.service.Groups.List().UserKey(email).Pages(ctx, func(page *admin.Groups) error {
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
