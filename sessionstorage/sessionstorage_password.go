package sessionstorage

import (
	"context"
	"fmt"
	"regexp"
	"time"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
)

var _ PasswordAuthStore = (*PasswordAuth)(nil)

// PasswordAuth is the session storage implementation with PasswordAuth support.
type PasswordAuth struct {
	sessionStorage
}

// NewSpannerPasswordAuth creates a new Password storage instance.
func NewSpannerPasswordAuth(client *cloudspanner.Client) *PasswordAuth {
	return &PasswordAuth{
		sessionStorage: sessionStorage{
			db: spanner.NewSessionStorageDriver(client),
		},
	}
}

// NewPostgresPassword creates a new PostgresPassword instance.
func NewPostgresPassword(pg postgres.Queryer) *PasswordAuth {
	return &PasswordAuth{
		sessionStorage: sessionStorage{
			db: postgres.NewSessionStorageDriver(pg),
		},
	}
}

// NewCustomSession creates a new session in the database, resolving custom session data via the resolver. The session's ID is returned.
func (p *PasswordAuth) NewCustomSession(ctx context.Context, username string, resolver dbtype.NewSessionCustomDataResolver) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	session := &dbtype.InsertSession{
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertCustomSession(ctx, session, resolver)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "db.InsertSession()")
	}

	return id, nil
}

// UpdateCustomSessionData updates the custom session data for an active session.
func (p *PasswordAuth) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, customData ...*sessioninfo.CustomData) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	session, err := p.db.Session(ctx, sessionID)
	if err != nil {
		return errors.Wrap(err, "db.Session()")
	}

	if session.Expired {
		return httpio.NewBadRequestMessage("cannot update custom session data for an expired session")
	}

	if err := p.db.UpdateCustomSessionData(ctx, sessionID, customData...); err != nil {
		return errors.Wrap(err, "db.UpdateCustomSessionData()")
	}

	return nil
}

// User returns the user record associated with the username
func (p *PasswordAuth) User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	u, err := p.db.User(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, "db.User()")
	}

	return u, nil
}

// UserByUserName returns the user record associated with the username
func (p *PasswordAuth) UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	u, err := p.db.UserByUserName(ctx, username)
	if err != nil {
		return nil, errors.Wrap(err, "db.UserByUserName()")
	}

	return u, nil
}

// CreateUser creates a new user
func (p *PasswordAuth) CreateUser(ctx context.Context, user *dbtype.InsertSessionUser) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	u, err := p.db.CreateUser(ctx, user)
	if err != nil {
		return nil, errors.Wrap(err, "db.CreateUser()")
	}

	return u, nil
}

// SetUserUsername updates the user username
func (p *PasswordAuth) SetUserUsername(ctx context.Context, id ccc.UUID, username string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.db.SetUserUsername(ctx, id, username); err != nil {
		return errors.Wrap(err, "db.SetUserUsername()")
	}

	return nil
}

// SetUserPasswordHash updates the user password hash
func (p *PasswordAuth) SetUserPasswordHash(ctx context.Context, id ccc.UUID, hash *securehash.Hash) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.db.SetUserPasswordHash(ctx, id, hash); err != nil {
		return errors.Wrap(err, "db.SetUserPasswordHash()")
	}

	return nil
}

// DeactivateUser deactivates a user
func (p *PasswordAuth) DeactivateUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.db.DeactivateUser(ctx, id); err != nil {
		return errors.Wrap(err, "db.DeactivateUser()")
	}

	return nil
}

// DeleteUser deletes a user
func (p *PasswordAuth) DeleteUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.db.DeleteUser(ctx, id); err != nil {
		return errors.Wrap(err, "db.DeleteUser()")
	}

	return nil
}

// ActivateUser activates a user
func (p *PasswordAuth) ActivateUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.db.ActivateUser(ctx, id); err != nil {
		return errors.Wrap(err, "db.ActivateUser()")
	}

	return nil
}

// DestroyAllUserSessions destroys all sessions for a given user
func (p *PasswordAuth) DestroyAllUserSessions(ctx context.Context, username string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.db.DestroyAllUserSessions(ctx, username); err != nil {
		return errors.Wrap(err, "db.DestroyAllUserSessions()")
	}

	return nil
}

var validColumnName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,127}$`)

// SetCustomSessionDataConfig sets the configuration for a separate custom session data table.
func (p *PasswordAuth) SetCustomSessionDataConfig(config *dbtype.CustomSessionDataConfig) {
	if !validColumnName.MatchString(config.TableName) {
		panic(fmt.Sprintf("invalid table name: %s. Table names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", config.TableName))
	}

	seen := make(map[string]struct{}, len(config.Columns))
	dedupedColumns := make([]string, 0, len(config.Columns))
	for _, name := range config.Columns {
		if !validColumnName.MatchString(name) {
			panic(fmt.Sprintf("invalid column name: %s. Column names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", name))
		}
		if dbtype.IsReservedCustomColumn(name) {
			panic(fmt.Sprintf("invalid column name: %s. This column name is reserved and cannot be used as a custom session data column.", name))
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		dedupedColumns = append(dedupedColumns, name)
	}

	p.db.SetCustomSessionDataConfig(&dbtype.CustomSessionDataConfig{
		TableName: config.TableName,
		Columns:   dedupedColumns,
		Decoder:   config.Decoder,
	})
}
