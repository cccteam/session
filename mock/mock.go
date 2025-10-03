// Package mock is used to generate mock files for testing.
package mock

//go:generate mockgen -source ../oidc/oidc_iface.go -destination mock_oidc/mock_oidc_iface.go
//go:generate mockgen -source ../oidc/loader/loader_iface.go -destination mock_loader/mock_loader_iface.go
//go:generate mockgen -source ../postgres/postgres_iface.go -destination mock_postgres/mock_postgres.go
//go:generate mockgen -source ../session_iface.go -destination mock_session/mock_session_iface.go
//go:generate mockgen -package session -source ../cookies.go -destination ../mock_cookies_test.go
