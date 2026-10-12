package sessionstorage

import (
	"context"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// The causes of a refused sign-in or identity operation, for errors.Is. A refused
// sign-in is also a sessioninfo.LoginRefusal, which carries the code the login page
// receives, and an Unauthorized client message.
var (
	// ErrIdentityRejected is the cause when the account resolver returned
	// RejectIdentity. The code is Resolution.Refusal, or
	// sessioninfo.RefusedIdentityRejected when that is empty.
	ErrIdentityRejected = dbtype.ErrIdentityRejected
	// ErrLinkRequiresConfirmation is the cause when the account resolver returned
	// LinkIdentity for an account that has a password, without TrustedForLinking. The
	// code is sessioninfo.RefusedIdentityRejected. The resolver should return
	// RequireConfirmation instead.
	ErrLinkRequiresConfirmation = dbtype.ErrLinkRequiresConfirmation
	// ErrSignInDenied is the cause when the sign-in policy returned DenySignIn or no
	// decision. The code is SignInDecision.Refusal, or sessioninfo.RefusedByPolicy.
	ErrSignInDenied = dbtype.ErrSignInDenied
	// ErrAccountDisabled is the cause when the sign-in resolved to a disabled account.
	// The code is sessioninfo.RefusedAccountDisabled.
	ErrAccountDisabled = dbtype.ErrAccountDisabled
	// ErrLastSignInMethod is returned when UnlinkIdentity would remove the last
	// identity of an account that has no password. It is a Conflict client message.
	ErrLastSignInMethod = dbtype.ErrLastSignInMethod
)

// PendingSignInError is returned by a session insert when the sign-in resolved to an
// account but must wait. Its Reason is sessioninfo.PendingConfirmation when the account
// resolver returned RequireConfirmation, and sessioninfo.PendingMFA when the sign-in
// policy returned RequireMFA. UserID is the account it waits on. No session is written,
// but the account resolution and the hooks' own writes are committed.
//
// After a password confirmation, link the identity (AccountStore.LinkIdentity) and
// insert the session with ReasonIdentityLinked. After MFA, insert it with ReasonStepUp,
// which the policy does not decide again. Use errors.As to read it.
type PendingSignInError = dbtype.PendingSignInError

// validateIdentities checks an identities configuration's table name and resolver.
func validateIdentities(tableName string, noResolver bool) error {
	if !validIdentifier.MatchString(tableName) {
		return errors.Newf("invalid table name: %s. Table names must start with a letter or underscore, followed by up to 127 letters, numbers, or underscores.", tableName)
	}
	if noResolver {
		return errors.New("an account resolver is required: it decides every external identity that is not linked yet")
	}

	return nil
}

// driverResolution converts an account resolver's answer for the drivers.
func driverResolution(r *Resolution) *dbtype.Resolution {
	if r == nil {
		return nil
	}

	return &dbtype.Resolution{
		Outcome:           dbtype.IdentityOutcome(r.Outcome),
		UserID:            r.UserID,
		NewUser:           r.NewUser,
		OnProvisioned:     r.OnProvisioned,
		Tenant:            r.Tenant,
		TrustedForLinking: r.TrustedForLinking,
		Refusal:           r.Refusal,
	}
}

// driverDecision converts a sign-in policy's answer for the drivers.
func driverDecision(d *SignInDecision) *dbtype.SignInDecision {
	if d == nil {
		return nil
	}

	return &dbtype.SignInDecision{Outcome: dbtype.PolicyOutcome(d.Outcome), Refusal: d.Refusal}
}

func (c *SpannerIdentities) driverConfig() *spanner.IdentitiesConfig {
	cfg := &spanner.IdentitiesConfig{
		TableName: c.tableName,
		Resolve: func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
			res, err := c.resolve(ctx, txn, req)

			return driverResolution(res), err
		},
	}
	if c.policy != nil {
		cfg.Policy = func(ctx context.Context, txn *cloudspanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*dbtype.SignInDecision, error) {
			d, err := c.policy(ctx, txn, req)

			return driverDecision(d), err
		}
	}

	return cfg
}

func (c *PostgresIdentities) driverConfig() *postgres.IdentitiesConfig {
	cfg := &postgres.IdentitiesConfig{
		TableName: c.tableName,
		Resolve: func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
			res, err := c.resolve(ctx, txn, req)

			return driverResolution(res), err
		},
	}
	if c.policy != nil {
		cfg.Policy = func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*dbtype.SignInDecision, error) {
			d, err := c.policy(ctx, txn, req)

			return driverDecision(d), err
		}
	}

	return cfg
}
