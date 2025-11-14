// Package mock is used to generate mock files for testing.
package mock

//go:generate mockgen -source ../internal/azureoidc/azureoidc_iface.go -destination mock_azureoidc/mock_azureoidc_iface.go
//go:generate mockgen -source ../internal/azureoidc/loader/loader_iface.go -destination mock_azureoidc/mock_loader/mock_loader_iface.go
//go:generate mockgen -source ../sessionstorage/internal/postgres/postgres_iface.go -destination mock_postgres/mock_postgres.go
//go:generate mockgen -source ../internal/basesession/basesession_iface.go -destination mock_basesession/mock_basesession_iface.go
//go:generate mockgen -source ../session_iface.go -destination mock_session/mock_session_iface.go
//go:generate mockgen -source ../internal/cookie/cookie_iface.go -destination mock_cookie/mock_cookie_iface.go
//go:generate mockgen -source ../sessionstorage/sessionstorage_iface.go -destination ../sessionstorage/mock/mock_sessionstorage/mock_sessionstorage.go
