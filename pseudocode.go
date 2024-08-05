package session

import (
	"context"

	"session/access"
)

type PasswordStorage interface {
	DestroySession(sessionID string) error
	Session(ctx context.Context, sessionID string) (*access.SessionInfo, error)
}

type OIDCStorage interface {
	DestroySession(sessionID string) error
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	Session(ctx context.Context, sessionID string) (*access.SessionInfo, error)
}

type Accessor interface {
	Domains(ctx context.Context) ([]access.Domain, error)
	UserRoles(ctx context.Context, username access.User, domain ...access.Domain) (map[access.Domain][]access.Role, error)
	RoleExists(ctx context.Context, role access.Role, domain access.Domain) bool
	AddUserRoles(ctx context.Context, user access.User, roles []access.Role, domain access.Domain) error
	DeleteUserRole(ctx context.Context, user access.User, role access.Role, domain access.Domain) error
}

type PasswordSession struct {
	Session
}

func NewPassword(driver PasswordStorage) *PasswordSession {
	return &PasswordSession{}
}

type OIDCSession struct {
	Session
}

func NewOIDC(driver OIDCStorage, access Accessor) *OIDCSession {
	return &OIDCSession{}
}

type SpannerDriver struct{}

func (s *SpannerDriver) DestroySession(sessionID string) error {
	return nil
}

func (s *SpannerDriver) Session(ctx context.Context, sessionID string) (*access.SessionInfo, error) {
	return nil, nil
}

func (s *SpannerDriver) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	return nil
}

type PostgresDriver struct{}

func (p *PostgresDriver) DestroySession(sessionID string) error {
	return nil
}

func (p *PostgresDriver) Session(ctx context.Context, sessionID string) (*access.SessionInfo, error) {
	return nil, nil
}

func (p *PostgresDriver) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	return nil
}

func Example() {
	_ = NewPassword(&SpannerDriver{})
	_ = NewPassword(&PostgresDriver{})
	_ = NewOIDC(&SpannerDriver{}, nil /* access.UserManager implementation */)
	_ = NewOIDC(&PostgresDriver{}, nil /* access.UserManager implementation */)
}
