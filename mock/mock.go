package mock

//go:generate mockgen -source ../oidc/oidc_iface.go -destination mock_oidc/mock_oidc_iface.go
//go:generate mockgen -source ../postgresql/postgresql_iface.go -destination mock_postgres/mock_postgres.go
//go:generate mockgen -source ../session_iface.go -destination mock_session/mock_session_iface.go
