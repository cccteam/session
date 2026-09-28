//go:build !skipAuth

package googlegroups

import (
	"context"
	"slices"
	"strings"
	"sync"

	"cloud.google.com/go/compute/metadata"
	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// Directory looks up a user's direct Google Groups memberships through the Admin SDK
// Directory API. The service behind it is built on first use, not at construction.
type Directory struct {
	opts []option.ClientOption
	// subject is the administrator the runtime identity impersonates through keyless
	// domain-wide delegation; empty when a key or opts authenticate instead.
	subject string

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
// credentialsJSON may be empty. With a subject, the delegation is keyless: the runtime
// identity, the service account the metadata server names on Google Cloud, signs a JWT
// for itself with the subject through the IAM Credentials API (iamcredentials.signJwt)
// and exchanges it for a Directory API token, so the application holds no key; that
// service account needs domain-wide delegation for the groups scope in the Workspace
// admin console and roles/iam.serviceAccountTokenCreator on itself, and off Google Cloud
// the first lookup fails naming the key as the way. With no subject either, opts carry
// the authentication (e.g. a token source, or an unauthenticated test endpoint), or
// Application Default Credentials stand.
//
// Construction is lazy. The inputs are validated here, but the Admin SDK service — and
// with it any credential resolution, including the fallback to Application Default
// Credentials when neither credentialsJSON nor opts authenticate — is built on the first
// UserGroups call. An application can therefore construct the adapter at startup in an
// environment without Google credentials; a credential problem surfaces from the first
// UserGroups, and from every later one.
func NewDirectory(ctx context.Context, credentialsJSON []byte, subject string, opts ...option.ClientOption) (*Directory, error) {
	if len(credentialsJSON) > 0 {
		if subject == "" {
			return nil, errors.New("subject is required with credentialsJSON: domain-wide delegation authorizes the service account only when impersonating an account with Groups-read privileges")
		}

		config, err := google.JWTConfigFromJSON(credentialsJSON, admin.AdminDirectoryGroupReadonlyScope)
		if err != nil {
			return nil, errors.Wrap(err, "google.JWTConfigFromJSON()")
		}
		config.Subject = subject

		return &Directory{opts: append([]option.ClientOption{option.WithTokenSource(config.TokenSource(ctx))}, opts...)}, nil
	}

	// The options outlive this call now, so the caller's slice is not the one kept.
	return &Directory{opts: slices.Clone(opts), subject: subject}, nil
}

// delegatedTokenSource is the keyless form of domain-wide delegation: the runtime identity
// (the service account the metadata server names) signs a JWT for itself with the subject
// through the IAM Credentials API and exchanges it for a Directory API token, so no key
// exists anywhere. The service account needs domain-wide delegation for the groups scope
// in the Workspace admin console and roles/iam.serviceAccountTokenCreator on itself.
func delegatedTokenSource(ctx context.Context, subject string, opts []option.ClientOption) (oauth2.TokenSource, error) {
	if !metadata.OnGCE() {
		return nil, errors.New("keyless domain-wide delegation needs the runtime identity, which only the metadata server names: " +
			"on Google Cloud the service account signs for itself; elsewhere pass a service-account key with domain-wide delegation as credentialsJSON")
	}
	principal, err := metadata.EmailWithContext(ctx, "default")
	if err != nil {
		return nil, errors.Wrap(err, "metadata.EmailWithContext(): the runtime identity for keyless domain-wide delegation")
	}
	source, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: principal,
		Scopes:          []string{admin.AdminDirectoryGroupReadonlyScope},
		Subject:         subject,
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "impersonate.CredentialsTokenSource(): %s signing for itself as %s", principal, subject)
	}

	return source, nil
}

// UserGroups returns the email addresses of the groups the user is a direct member of,
// lowercased.
//
// The lookup names the user's own domain, the part of email after the @, beside the
// user. The Directory API resolves the Workspace customer from that domain; without it
// the API infers the customer from the caller, which works for a signed-in
// administrator and answers 404 "Domain not found" for a service account holding an
// admin role, the keyless deployment. Role groups therefore live in the login's domain,
// which the hosted-domain restriction on the sign-in already guarantees.
//
// The first call builds the Admin SDK service (see NewDirectory). When that fails —
// typically because no credentials could be resolved — the construction error is
// returned by this call and, unchanged, by every later one: the Directory does not
// retry, so a misconfigured adapter fails the same way on each login rather than
// re-resolving credentials every time.
func (d *Directory) UserGroups(ctx context.Context, email string) ([]string, error) {
	domain, err := domainOf(email)
	if err != nil {
		return nil, err
	}

	service, err := d.adminService(ctx)
	if err != nil {
		return nil, err
	}

	var groups []string
	err = service.Groups.List().UserKey(email).Domain(domain).Pages(ctx, func(page *admin.Groups) error {
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
		ctx := context.WithoutCancel(ctx)
		opts := d.opts
		if d.subject != "" {
			source, err := delegatedTokenSource(ctx, d.subject, opts)
			if err != nil {
				d.buildErr = err

				return
			}
			opts = append([]option.ClientOption{option.WithTokenSource(source)}, opts...)
		}
		service, err := admin.NewService(ctx, opts...)
		if err != nil {
			d.buildErr = errors.Wrap(err, "admin.NewService()")

			return
		}
		d.service = service
	})

	return d.service, d.buildErr
}

// domainOf is the domain of an email address, lowercased: what the groups lookup names
// beside the user. An address with no domain cannot be looked up at all.
func domainOf(email string) (string, error) {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return "", errors.Newf("user %q has no domain to look groups up in", email)
	}

	return strings.ToLower(email[at+1:]), nil
}
