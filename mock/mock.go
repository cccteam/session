// Package mock is used to generate mock files for testing.
package mock

//go:generate mockgen -source ../internal/azureoidc/azureoidc_iface.go -destination mock_azureoidc/mock_azureoidc_iface.go
//go:generate mockgen -source ../internal/googleoidc/googleoidc_iface.go -destination mock_googleoidc/mock_googleoidc_iface.go
//go:generate mockgen -source ../session_iface.go -destination mock_session/mock_session_iface.go
//go:generate mockgen -source ../internal/cookie/cookie_iface.go -destination mock_cookie/mock_cookie_iface.go
//go:generate mockgen -source ../sessionstorage/sessionstorage_iface.go -destination ../sessionstorage/mock/mock_sessionstorage/mock_sessionstorage.go -exclude_interfaces db
//go:generate mockgen -source ../sessionstorage/sessionstorage_iface.go -destination ../sessionstorage/db_mock_test.go -package sessionstorage -exclude_interfaces BaseStore,PreauthStore,PasswordAuthStore,OIDCStore,GoogleOIDCStore
