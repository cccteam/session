// Package sessionstorage implements database storage for session data.
// There are implementations for both Spanner and Postgres for each
// session type (i.e. OIDC, Username/Password, etc)
package sessionstorage

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
)

// BaseStore defines an interface for managing session storage.
type BaseStore interface {
	// Session returns the session information from the database for given sessionID
	Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionData, error)
	// UpdateCustomSessionData updates the custom session data for an active session via
	// a transactional read-modify-write: mutate receives the current row as *T for the
	// configured struct type (zero-value when no row exists) and the full row is written
	// back; a mutate error aborts with nothing written. For genuine mid-session updates
	// only — initial population belongs in the session-creation transaction.
	UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data any) error) error
	// CustomDataType returns the struct type the attached custom session data
	// configuration was built for, or nil when no configuration is attached.
	CustomDataType() reflect.Type
	// CustomUserDataType returns the struct type the attached custom user data
	// configuration was built for, or nil when no configuration is attached.
	CustomUserDataType() reflect.Type
	// UserDataLoginHookConfigured reports whether the attached custom user data
	// configuration carries an OIDC login hook.
	UserDataLoginHookConfigured() bool
	// OIDCUsersEnabled reports whether the library-managed OIDC user anchor is enabled.
	OIDCUsersEnabled() bool
	// UpdateSessionActivity updates the database with the current time for the session activity
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	// DestroySession marks the session as expired
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
	// SetSessionTableName sets the name of the session table.
	SetSessionTableName(name string)
	// SetUserTableName sets the name of the user table.
	SetUserTableName(name string)
	// SetOIDCUserTableName sets the name of the OIDC user anchor table.
	SetOIDCUserTableName(name string)
}

var _ PreauthStore = (*Preauth)(nil)

// PreauthStore defines an interface for managing pre-authenticated session storage.
type PreauthStore interface {
	// NewSession creates a new session in the database, returning its id. customData
	// is nil or *T for the configured custom session data struct type; when non-nil it
	// is written atomically with the session insert and requires a custom session data
	// configuration on the storage.
	NewSession(ctx context.Context, username string, customData any) (ccc.UUID, error)
	// DestroyAllUserSessions destroys all sessions for a given user
	DestroyAllUserSessions(ctx context.Context, username string) error

	// shared storage methods
	BaseStore
}

var _ PasswordAuthStore = (*PasswordAuth)(nil)

// SessionUser is a person authorized to access the application.
type SessionUser = dbtype.SessionUser

// InsertSessionUser defines the structure for inserting a new SessionUser.
type InsertSessionUser = dbtype.InsertSessionUser

// PasswordAuthStore defines an interface for managing password sessions.
type PasswordAuthStore interface {
	// CreateSession creates a new session for the request and returns its ID. When a
	// custom session data configuration with a resolver is attached to the storage, the
	// resolver runs inside the session-insert transaction; a resolver error aborts
	// session creation. With no resolver it is a plain insert.
	CreateSession(ctx context.Context, req *sessioninfo.NewSessionRequest) (ccc.UUID, error)
	// User returns a session user for give user id
	User(ctx context.Context, id ccc.UUID) (*SessionUser, error)
	// UserByUsername returns a session user for give username
	UserByUserName(ctx context.Context, username string) (*SessionUser, error)
	// SetUserUsername updates the user username and, atomically, the Username
	// on every active session row for that user.
	SetUserUsername(ctx context.Context, id ccc.UUID, newUsername string) error
	// SetUserPasswordHash updates the user password hash
	SetUserPasswordHash(ctx context.Context, id ccc.UUID, hash *securehash.Hash) error
	// ActivateUser activates a user
	ActivateUser(ctx context.Context, id ccc.UUID) error
	// CreateUser creates a new user. customData is nil or *U for the configured custom
	// user data struct type; when non-nil it is written atomically with the user insert
	// and requires a custom user data configuration on the storage.
	CreateUser(ctx context.Context, user *InsertSessionUser, customData any) (*SessionUser, error)
	// DeactivateUser deactivates a user
	DeactivateUser(ctx context.Context, id ccc.UUID) error
	// DeleteUser deletes a user
	DeleteUser(ctx context.Context, id ccc.UUID) error
	// DestroyAllUserSessions destroys all sessions for a given user
	DestroyAllUserSessions(ctx context.Context, username string) error
	// CustomUserData returns the custom user data row for the given user ID as *U for
	// the configured struct type. A user with no custom data row yields a zero-value *U.
	CustomUserData(ctx context.Context, userID ccc.UUID) (any, error)
	// UpdateCustomUserData updates the custom user data for an existing user via a
	// transactional read-modify-write: mutate receives the current row as *U (zero-value
	// when no row exists) and the full row is written back; a mutate error aborts with
	// nothing written.
	UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data any) error) error

	// shared storage methods
	PreauthStore
}

var _ OIDCStore = (*OIDC)(nil)

// OIDCUser is a library-managed durable user record for OIDC logins, keyed by the
// immutable (Tid, Oid) claim pair with a surrogate UUID primary key.
type OIDCUser = dbtype.OIDCUser

// OIDCStore defines an interface for managing OIDC session storage.
type OIDCStore interface {
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	// NewSession creates a new OIDC session. claims carries the raw verified ID-token
	// claims into any configured custom session data resolver, which runs inside the
	// session-insert transaction; a resolver error aborts session creation. When the
	// OIDC user anchor is enabled the same transaction upserts the OIDCUsers record for
	// the claims' (tid, oid) and runs any configured custom user data hook.
	NewSession(ctx context.Context, username, oidcSID string, claims json.RawMessage) (ccc.UUID, error)
	// OIDCUser returns the OIDC user anchor record for the given ID.
	OIDCUser(ctx context.Context, id ccc.UUID) (*OIDCUser, error)
	// OIDCUserByKey returns the OIDC user anchor record for the given (tid, oid) claim pair.
	OIDCUserByKey(ctx context.Context, tid, oid string) (*OIDCUser, error)
	// CustomUserData returns the custom user data row for the given user ID as *U for
	// the configured struct type. A user with no custom data row yields a zero-value *U.
	CustomUserData(ctx context.Context, userID ccc.UUID) (any, error)
	// UpdateCustomUserData updates the custom user data for an existing user via a
	// transactional read-modify-write: mutate receives the current row as *U (zero-value
	// when no row exists) and the full row is written back; a mutate error aborts with
	// nothing written.
	UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data any) error) error

	// shared storage methods
	BaseStore
}

// GoogleOIDCUser is a library-managed durable user record for Google OIDC logins, keyed
// by the immutable, globally unique Sub claim with a surrogate UUID primary key.
type GoogleOIDCUser = dbtype.GoogleOIDCUser

// GoogleOIDCStore defines an interface for managing Google OIDC session storage.
type GoogleOIDCStore interface {
	// NewSession creates a new Google OIDC session. claims carries the raw verified
	// ID-token claims into any configured custom session data resolver, which runs
	// inside the session-insert transaction; a resolver error aborts session creation.
	// When the OIDC user anchor is enabled the same transaction upserts the
	// GoogleOIDCUsers record for the claims' sub and runs any configured custom user
	// data hook.
	NewSession(ctx context.Context, username string, claims json.RawMessage) (ccc.UUID, error)
	// GoogleOIDCUser returns the Google OIDC user anchor record for the given ID.
	GoogleOIDCUser(ctx context.Context, id ccc.UUID) (*GoogleOIDCUser, error)
	// GoogleOIDCUserBySub returns the Google OIDC user anchor record for the given sub claim.
	GoogleOIDCUserBySub(ctx context.Context, sub string) (*GoogleOIDCUser, error)
	// CustomUserData returns the custom user data row for the given user ID as *U for
	// the configured struct type. A user with no custom data row yields a zero-value *U.
	CustomUserData(ctx context.Context, userID ccc.UUID) (any, error)
	// UpdateCustomUserData updates the custom user data for an existing user via a
	// transactional read-modify-write: mutate receives the current row as *U (zero-value
	// when no row exists) and the full row is written back; a mutate error aborts with
	// nothing written.
	UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data any) error) error

	// shared storage methods
	BaseStore
}

var (
	_ db = (*spanner.SessionStorageDriver)(nil)
	_ db = (*postgres.SessionStorageDriver)(nil)
)

// db defines an interface for database operations related to session management.
type db interface {
	// Session returns the session information from the database for given sessionID.
	Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.SessionData, error)
	// InsertSession inserts a Session into the database and returns its id. When a custom
	// session data configuration with a resolver is attached, the resolver runs within the
	// same transaction as the session insert; a resolver error aborts the insert.
	InsertSession(ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error)
	// UpdateCustomSessionData updates the custom session data for an active session via a
	// transactional read-modify-write of the full row.
	UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data any) error) error
	// CustomDataType returns the struct type of the attached custom session data configuration, or nil.
	CustomDataType() reflect.Type
	// CustomUserDataType returns the struct type of the attached custom user data configuration, or nil.
	CustomUserDataType() reflect.Type
	// UserDataLoginHookConfigured reports whether the attached custom user data configuration carries an OIDC login hook.
	UserDataLoginHookConfigured() bool
	// OIDCUsersEnabled reports whether the library-managed OIDC user anchor is enabled.
	OIDCUsersEnabled() bool
	// CustomUserData returns the custom user data row for the given user ID as *U
	// (zero-value *U when no row exists).
	CustomUserData(ctx context.Context, userID ccc.UUID) (any, error)
	// UpdateCustomUserData updates the custom user data for an existing user via a
	// transactional read-modify-write of the full row.
	UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data any) error) error
	// UpdateSessionActivity updates the session activity column with the current time.
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	// DestroySession marks the session as expired.
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
	// SetSessionTableName sets the name of the session table.
	SetSessionTableName(name string)
	// SetUserTableName sets the name of the user table.
	SetUserTableName(name string)
	// SetOIDCUserTableName sets the name of the OIDC user anchor table.
	SetOIDCUserTableName(name string)

	//
	// Password specific methods
	//

	// User returns a session user for give user id
	User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error)
	// UserByUsername returns a session user for give username
	UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error)
	// SetUserUsername updates the user username and, atomically, the Username
	// on every active session row for that user.
	SetUserUsername(ctx context.Context, id ccc.UUID, newUsername string) error
	// SetUserPasswordHash updates the user password hash
	SetUserPasswordHash(ctx context.Context, id ccc.UUID, hash *securehash.Hash) error
	// ActivateUser activates a user
	ActivateUser(ctx context.Context, id ccc.UUID) error
	// CreateUser creates a new user; non-nil customData (*U) is written atomically with the user insert.
	CreateUser(ctx context.Context, insertSessionUser *dbtype.InsertSessionUser, customData any) (*dbtype.SessionUser, error)
	// DeactivateUser deactivates a user
	DeactivateUser(ctx context.Context, id ccc.UUID) error
	// DeleteUser deletes a user
	DeleteUser(ctx context.Context, id ccc.UUID) error
	// DestroyAllUserSessions destroys all sessions for a given user
	DestroyAllUserSessions(ctx context.Context, username string) error

	//
	// OIDC specific methods
	//

	// InsertSessionOIDC creates a new OIDC session in the database and returns its session ID.
	// It honors the request's custom session data semantics (per-call data or configured resolver, atomic with the insert).
	// When the OIDC user anchor is enabled the same transaction upserts the anchor row and runs any configured custom user data hook.
	InsertSessionOIDC(ctx context.Context, session *dbtype.InsertOIDCSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error)
	// DestroySessionOIDC marks the OIDC session as expired by oidcSID.
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	// OIDCUser returns the OIDC user anchor record for the given ID.
	OIDCUser(ctx context.Context, id ccc.UUID) (*dbtype.OIDCUser, error)
	// OIDCUserByKey returns the OIDC user anchor record for the given (tid, oid) claim pair.
	OIDCUserByKey(ctx context.Context, tid, oid string) (*dbtype.OIDCUser, error)

	//
	// Google OIDC specific methods
	//

	// InsertSessionGoogleOIDC creates a new Google OIDC session in the database and returns its session ID.
	// Google issues no sid claim, so the session row carries no OidcSid; the custom data semantics match InsertSessionOIDC.
	// When the OIDC user anchor is enabled the same transaction upserts the Sub-keyed anchor row and runs any configured custom user data hook.
	InsertSessionGoogleOIDC(ctx context.Context, session *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error)
	// GoogleOIDCUser returns the Google OIDC user anchor record for the given ID.
	GoogleOIDCUser(ctx context.Context, id ccc.UUID) (*dbtype.GoogleOIDCUser, error)
	// GoogleOIDCUserBySub returns the Google OIDC user anchor record for the given sub claim.
	GoogleOIDCUserBySub(ctx context.Context, sub string) (*dbtype.GoogleOIDCUser, error)
}
