# Session

## Overview

The Session repository is designed to handle the management of user sessions, including authorization, storage, and expiration. It provides a framework for manageing sessions across different databases and supports multiple login types.

## Features

- `Session Management`: Efficient handling of user session creation, storage, and expiration.
- `Database Support`: Seamless integration with multiple databases.
  - PostgreSQL
  - Google Cloud Spanner
- `Login Types`: Supports multiple authentication methods.
  - Azure OIDC
  - Username/Password

## Usage

### Reacting to a successful OIDC login

When using `Azure OIDC`, you can register an `OnAuthenticatedFunc` callback with the
`WithOnAuthenticated` option. It runs after a successful login, once the session has been
initialized, and receives the session ID and the verified ID-token claims, including the
immutable Entra object id (`oid`). This is a convenient place to do just-in-time user
provisioning or profile syncing without an extra Microsoft Graph lookup.

The callback is informational: it cannot block the login, so handle and log any errors within it.

```go
oidcAzure, err := session.NewOIDCAzure(
    storage, userRoleManager,
    cookieKey,
    issuerURL, clientID, clientSecret, redirectURL,
    session.WithOnAuthenticated(func(ctx context.Context, sessionID ccc.UUID, claims session.Claims) {
        // Provision/sync the user in your own datastore, keyed by the immutable object id.
        // This is informational — the login proceeds regardless, so handle/log errors here.
        _ = users.Upsert(ctx, UserProfile{
            Oid:      claims.Oid,      // immutable, safe to use as a primary key
            Username: claims.Username, // preferred_username (mutable)
            Name:     claims.Name,
            Email:    claims.Email,    // may be empty depending on optional-claims config
        })
    }),
)
if err != nil {
    // handle err
}
```

##### Created and maintained by the CCC team.
