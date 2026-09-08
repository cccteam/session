// Package googlegroups provides Google Groups membership lookups for Google OIDC role
// synchronization. Google ID tokens carry no roles or groups claim, so group membership
// — the raw material for role sync — must be fetched from a Google API at login.
//
// Directory is the adapter for the Admin SDK Directory API, which is available on every
// Google Workspace edition and returns the groups a user is a DIRECT member of (nested
// membership is not expanded — role groups should hold people, not other groups). It
// authenticates as a service account with domain-wide delegation, impersonating an
// account that holds a Groups-read admin privilege.
//
// A CloudIdentity adapter (Cloud Identity API searchTransitiveGroups: nested expansion,
// Groups Reader admin role instead of domain-wide delegation) is intentionally left for
// the future: that API is limited to Workspace Enterprise / Cloud Identity Premium
// accounts, enforced per queried member.
//
// Under the skipAuth build tag the adapter is the simulated directory: NewDirectory needs
// no credentials, and UserGroups answers a person's groups from APP_ROLES (one group per
// role, spelled <role>@skipauth.invalid), the way the simulated login answers who they are
// from APP_USERNAME. The session package reads such a group as its role outright under the
// same tag, so a directory-run Google auth can be signed in to in development. A
// development application constructs the adapter exactly as a deployed one does.
package googlegroups
