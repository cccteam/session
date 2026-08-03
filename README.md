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

When using `Azure OIDC`, register an `OnAuthenticatedFunc` callback with the `WithOnAuthenticated`
option. It runs after a successful login with the session ID and the verified ID-token claims,
which is useful for just-in-time user provisioning. The callback is informational: it cannot block
the login, so handle and log any errors within it.

```go
oidcAzure, err := session.NewOIDCAzure(
    storage, userRoleManager,
    cookieKey,
    issuerURL, clientID, clientSecret, redirectURL,
    session.WithOnAuthenticated(func(ctx context.Context, sessionID ccc.UUID, claims session.Claims) {
        _ = users.Upsert(ctx, UserProfile{
            Oid:      claims.Oid, // immutable object id, safe to use as a primary key
            Username: claims.Username,
            Name:     claims.Name,
            Email:    claims.Email,
        })
    }),
)
if err != nil {
    // handle err
}
```

##### Created and maintained by the CCC team.
