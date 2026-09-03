package sessionstorage

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
)

// ImpersonationTable is the validated impersonation configuration for storage of
// either backend: the name of the impersonation record table. Build it with
// NewImpersonationTable and attach it via WithImpersonation.
//
// The library ships the table's canonical DDL under
// schema/{spanner,postgresql}/impersonation/migrations; the record deliberately has
// no foreign key to the session table, so it outlives the session as evidence.
type ImpersonationTable struct {
	tableName string
}

// NewImpersonationTable validates and builds an impersonation configuration for the
// record table named tableName.
func NewImpersonationTable(tableName string) (*ImpersonationTable, error) {
	if !validIdentifier.MatchString(tableName) {
		return nil, errors.Newf("invalid table name: %s. Table names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", tableName)
	}

	return &ImpersonationTable{tableName: tableName}, nil
}

// TableName returns the impersonation record table name.
func (t *ImpersonationTable) TableName() string {
	return t.tableName
}

type impersonationOption struct {
	tableName string
}

func (o impersonationOption) applySpanner(driver *spanner.SessionStorageDriver) {
	driver.SetImpersonation(&spanner.ImpersonationConfig{TableName: o.tableName})
}

func (o impersonationOption) applyPostgres(driver *postgres.SessionStorageDriver) {
	driver.SetImpersonation(&postgres.ImpersonationConfig{TableName: o.tableName})
}

// WithImpersonation enables impersonated sessions on storage of either backend. The
// record table is LEFT JOINed into every session read, so an impersonated session's
// record reaches the request context together with the session, and it is written
// atomically with the session insert by CreateImpersonatedSession. Without this option
// no session is ever impersonated and the impersonation APIs return a configuration
// error. See the "Impersonated sessions" section of the README.
func WithImpersonation(table *ImpersonationTable) Option {
	return impersonationOption{tableName: table.tableName}
}

// ImpersonationEnabled reports whether an impersonation record table is configured.
func (s *sessionStorage) ImpersonationEnabled() bool {
	return s.db.ImpersonationEnabled()
}

// EndImpersonation records how an impersonated session ended, once: it sets EndedAt
// and EndReason on the session's impersonation record when the record exists and has
// not already ended, and is a no-op otherwise.
func (s *sessionStorage) EndImpersonation(ctx context.Context, sessionID ccc.UUID, reason sessioninfo.ImpersonationEndReason) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := s.db.EndImpersonation(ctx, sessionID, string(reason)); err != nil {
		return errors.Wrap(err, "db.EndImpersonation()")
	}

	return nil
}

// CreateImpersonatedSession creates a new session for the request together with its
// impersonation record, atomically, and returns the session ID. Custom session data
// follows the session type's creation semantics inside the same transaction. The
// request's Username is written as the session's effective identity; no user record is
// consulted here — the session type resolved the identity before calling.
func (s *sessionStorage) CreateImpersonatedSession(ctx context.Context, req *sessioninfo.NewSessionRequest, imp *sessioninfo.Impersonation) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	session := &dbtype.InsertSession{
		Username:  req.Username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := s.db.InsertImpersonatedSession(ctx, session, req, dbtype.NewInsertImpersonation(imp))
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "db.InsertImpersonatedSession()")
	}

	return id, nil
}

// CreateImpersonatedSession creates a new OIDC session for the request together with
// its impersonation record, atomically, and returns the session ID. The row carries an
// empty OidcSid: no identity provider authenticated this session, so no front-channel
// logout ever names it (FrontChannelLogout refuses an empty sid) — an impersonated
// session ends by its hard cap, idle expiry, Logout, or DestroyImpersonatedSessions.
// The OIDC user anchor is left untouched for the same reason: there are no claims.
func (s *OIDC) CreateImpersonatedSession(ctx context.Context, req *sessioninfo.NewSessionRequest, imp *sessioninfo.Impersonation) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	session := &dbtype.InsertOIDCSession{
		InsertSession: dbtype.InsertSession{
			Username:  req.Username,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	id, err := s.db.InsertImpersonatedSessionOIDC(ctx, session, req, dbtype.NewInsertImpersonation(imp))
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "db.InsertImpersonatedSessionOIDC()")
	}

	return id, nil
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor and ends their records with reason Revoked.
func (s *sessionStorage) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := s.db.DestroyImpersonatedSessions(ctx, actor); err != nil {
		return errors.Wrap(err, "db.DestroyImpersonatedSessions()")
	}

	return nil
}

// ActiveImpersonations lists the impersonated sessions that are live, newest first:
// record not ended, hard cap not passed, session row not expired, and session activity
// after activeSince; q narrows the listing by actor and/or principal.
func (s *sessionStorage) ActiveImpersonations(ctx context.Context, activeSince time.Time, q *sessioninfo.ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	rows, err := s.db.ActiveImpersonations(ctx, activeSince, q)
	if err != nil {
		return nil, errors.Wrap(err, "db.ActiveImpersonations()")
	}

	imps := make([]*sessioninfo.Impersonation, len(rows))
	for i, row := range rows {
		imps[i] = row.ToSessionInfo()
	}

	return imps, nil
}
