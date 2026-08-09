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

## Custom session data from Azure OIDC claims

A custom session data resolver runs inside the session-insert transaction, once per
session creation; returning an error aborts the login before any cookie is written.
For OIDC logins the resolver receives the raw verified ID-token claims on the request
(`req.Claims`) — the library does not curate a claims struct; unmarshal the fields you
need. The decoder runs on every authenticated request and must tolerate all-nil values
(a session without a custom data row reads back via LEFT JOIN).

```go
type SessionClaims struct {
    Oid   string `json:"oid"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

customCfg, err := sessionstorage.NewSpannerCustomSessionData(
    "SessionClaimsData",
    func(m map[string]any) (SessionClaims, error) {
        c := SessionClaims{}
        c.Oid, _ = m["Oid"].(string)
        c.Name, _ = m["Name"].(string)
        c.Email, _ = m["Email"].(string)
        return c, nil
    },
    func(ctx context.Context, txn *spanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) ([]*sessioninfo.CustomData, error) {
        var c SessionClaims
        if err := json.Unmarshal(req.Claims, &c); err != nil {
            return nil, err
        }
        // Optionally JIT-provision an app user record here, keyed on the immutable oid,
        // using txn so provisioning commits atomically with the session.
        return []*sessioninfo.CustomData{
            {ColumnName: "Oid", Value: c.Oid},
            {ColumnName: "Name", Value: c.Name},
            {ColumnName: "Email", Value: c.Email},
        }, nil
    },
    "Oid", "Name", "Email",
)
if err != nil {
    // invalid table/column name, reserved "SessionId", nil decoder, ...
}

oidcSession, err := session.NewOIDCAzure(
    sessionstorage.NewSpannerOIDC(client, sessionstorage.WithSpannerCustomSessionData(customCfg)),
    userRoleManager, cookieKey, issuerURL, clientID, clientSecret, redirectURL,
)
```

The required DDL: a table whose primary key column `SessionId` is a foreign key to the
session table's primary key with `ON DELETE CASCADE`; never list `SessionId` in the
column names (it is implied). Handlers read the typed value back with
`sessioninfo.CustomDataFromCtx[SessionClaims](ctx)`.

##### Created and maintained by the CCC team.
