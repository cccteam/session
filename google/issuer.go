package google

// IssuerURL is Google's OIDC issuer. Google uses one issuer for every Workspace
// organization; the hd claim names the organization. It is a variable only so this
// module's end-to-end tests can point a sign-in at a fake identity provider. SignIn
// declares it as the registration's issuer, and NewOIDC reads it when the
// authenticator is built.
var IssuerURL = "https://accounts.google.com"
