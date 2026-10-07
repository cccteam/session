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

// The causes a refused sign-in or identity operation carries, for errors.Is. A refused
// sign-in is also a sessioninfo.LoginRefusal, whose code (sessioninfo.LoginRefusalCodeOf)
// the login page receives, and an Unauthorized client message.
var (
	// ErrIdentityRejected: the account resolver returned RejectIdentity. The refusal code
	// is Resolution.Refusal, or sessioninfo.RefusedIdentityRejected when it is empty.
	ErrIdentityRejected = dbtype.ErrIdentityRejected
	// ErrLinkRequiresConfirmation: the account resolver returned LinkIdentity for an
	// account that has a password, without TrustedForLinking. Code
	// sessioninfo.RefusedIdentityRejected; the resolver should return RequireConfirmation.
	ErrLinkRequiresConfirmation = dbtype.ErrLinkRequiresConfirmation
	// ErrSignInDenied: the sign-in policy returned DenySignIn (or no decision). The
	// refusal code is SignInDecision.Refusal, or sessioninfo.RefusedByPolicy.
	ErrSignInDenied = dbtype.ErrSignInDenied
	// ErrAccountDisabled: the sign-in resolved to a disabled account. Code
	// sessioninfo.RefusedAccountDisabled.
	ErrAccountDisabled = dbtype.ErrAccountDisabled
	// ErrLastSignInMethod: UnlinkIdentity refused to remove the last identity of an
	// account that has no password (a Conflict client message).
	ErrLastSignInMethod = dbtype.ErrLastSignInMethod
)

// PendingSignInError is the error a session insert returns when the sign-in resolved
// but must wait: the account resolver returned RequireConfirmation (Reason
// sessioninfo.PendingConfirmation, UserID the account to confirm against) or the sign-in
// policy returned RequireMFA (Reason sessioninfo.PendingMFA, UserID the account). No
// session is written while a sign-in waits; the hooks' own writes and the account
// resolution are committed, so an account the sign-in provisioned exists, linked, and an
// MFA wait names it. Completing it inserts the session again: with ReasonStepUp after
// MFA, which the policy does not decide (the identity is linked by then), or, after a
// password confirmation, by linking the identity (AccountStore.LinkIdentity) and
// inserting with ReasonIdentityLinked. Use errors.As to read it.
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
