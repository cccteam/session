// Package drivertest is the conformance suite the PostgreSQL and Spanner drivers share.
// The two drivers must implement identical semantics, and until this package existed
// that equivalence rested on two near-identical test files being edited in step. Each
// driver package now supplies a Harness and runs the suite; a case added here runs
// against both backends, and a case that passes on one and fails on the other is a
// divergence, which is exactly what the suite exists to catch.
package drivertest

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
)

// Driver is the driver surface the suite exercises. Both drivers satisfy it.
type Driver interface {
	Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.SessionData, error)
	InsertSession(ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error)
	InsertImpersonatedSession(ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation) (ccc.UUID, error)
	InsertImpersonatedSessionOIDC(ctx context.Context, session *dbtype.InsertOIDCSession, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation) (ccc.UUID, error)
	EndImpersonation(ctx context.Context, sessionID ccc.UUID, reason string) error
	DestroyImpersonatedSessions(ctx context.Context, actor string) error
	DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID, reason string) error
	ActiveImpersonations(ctx context.Context, activeSince time.Time, q *sessioninfo.ImpersonationQuery) ([]*dbtype.Impersonation, error)
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
	DestroyAllUserSessions(ctx context.Context, username string) error
	CreateUser(ctx context.Context, user *dbtype.InsertSessionUser, customData any) (*dbtype.SessionUser, error)
	SetUserUsername(ctx context.Context, userID ccc.UUID, newUsername string) error
}

// Schema names the migration set a database is prepared with.
type Schema int

const (
	// SeededImpersonation is the driver package's impersonation fixture: sessions, the
	// custom session data table, the impersonation table, and the seeded rows the
	// Seeded* identifiers below name.
	SeededImpersonation Schema = iota
	// Sessions is the shipped sessions schema (Sessions, SessionUsers) plus the shipped
	// impersonation migration.
	Sessions
	// OIDC is the shipped OIDC sessions schema plus the shipped impersonation migration.
	OIDC
)

// Config selects how a driver over a prepared database is configured.
type Config struct {
	// Impersonation attaches the SessionImpersonations table.
	Impersonation bool
	// CustomData attaches the SessionCustomData table with a codec for CustomStringData.
	CustomData bool
	// Google builds the Google OIDC flavor of the driver.
	Google bool
}

// CustomStringData is the custom session data row the SeededImpersonation schema's
// SessionCustomData table holds. The tags cover both drivers' codecs.
type CustomStringData struct {
	CustomString string `db:"CustomString" spanner:"CustomString"`
}

// Instance is a driver over a freshly prepared database, with the harness's own handle
// on that database for the direct reads and writes some cases need.
type Instance struct {
	Driver Driver
	// NewDriver builds another driver over the same database, configured per cfg.
	NewDriver func(cfg Config) Driver
	// Raw is the harness's handle to the database: a pool, a client. The harness's
	// readers below receive it back.
	Raw any
}

// Harness adapts one driver package to the suite.
type Harness struct {
	// New prepares a fresh database with schema and returns a driver configured per cfg.
	New func(ctx context.Context, t *testing.T, schema Schema, cfg Config) *Instance
	// RecordEnd reads the end columns of the session's impersonation record straight
	// from the table: nil, nil while it is live.
	RecordEnd func(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID) (endedAt *time.Time, endReason *string)
	// ExpireSession marks the session row expired directly, bypassing the driver.
	ExpireSession func(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID)
	// OIDCSid reads the session row's identity provider session ID directly.
	OIDCSid func(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID) string
}

// The rows the SeededImpersonation schema seeds. Every seeded record is past its hard
// cap (2026-08-27) so none is ever active.
var (
	// SeededImpersonatedUser is bob@partner.org, impersonated read-only by the foreign
	// actor alice@example.com with every optional column set; live.
	SeededImpersonatedUser = ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111"))
	// SeededImpersonatedRole is alice@example.com under PartnerViewer, ended Logout,
	// nullable columns NULL; the row is expired.
	SeededImpersonatedRole = ccc.Must(ccc.UUIDFromString("22222222-2222-2222-2222-222222222222"))
	// SeededPlain is plain_user, not impersonated.
	SeededPlain = ccc.Must(ccc.UUIDFromString("33333333-3333-3333-3333-333333333333"))
	// SeededImpersonatedCarol is carol@partner.org, impersonated by the local actor
	// alice@example.com with the empty mask; live.
	SeededImpersonatedCarol = ccc.Must(ccc.UUIDFromString("44444444-4444-4444-4444-444444444444"))
	// SeededImpersonatedByDave is dave@example.com under Editor; live.
	SeededImpersonatedByDave = ccc.Must(ccc.UUIDFromString("66666666-6666-6666-6666-666666666666"))
	// SeededSource is the source session the first record names.
	SeededSource = ccc.Must(ccc.UUIDFromString("55555555-5555-5555-5555-555555555555"))
)

func strPtr(s string) *string { return &s }

func timePtr(t time.Time) *time.Time { return &t }

// reasonOf renders a record's end reason, "" for a live record.
func reasonOf(reason *string) string {
	if reason == nil {
		return ""
	}

	return *reason
}
