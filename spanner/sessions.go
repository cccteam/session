package spanner

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/spxscan"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/codes"
)

// Session returns the session information from the database for given sessionID
func (c *Client) Session(ctx context.Context, sessionID ccc.UUID) (*Session, error) {
	_, span := otel.Tracer(name).Start(ctx, "client.Session()")
	defer span.End()

	stmt := spanner.NewStatement(`
		SELECT
			Id, OidcSid, Username, CreatedAt, UpdatedAt, Expired
		FROM Sessions
		WHERE Id = @id
	`)
	stmt.Params["id"] = sessionID

	s := &Session{}
	if err := spxscan.Get(ctx, c.spanner.Single(), s, stmt); err != nil {
		if errors.Is(err, spxscan.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("session %q not found", sessionID)
		}

		return nil, errors.Wrapf(err, "failed to scan row for session %q", sessionID)
	}

	return s, nil
}

// InsertSession inserts a Session into database
func (c *Client) InsertSession(ctx context.Context, insertSession *InsertSession) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.InsertSession()")
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	session := &struct {
		ID ccc.UUID
		*InsertSession
	}{
		ID:            id,
		InsertSession: insertSession,
	}

	mutation, err := spanner.InsertStruct("Sessions", session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.InsertStruct()")
	}
	if _, err := c.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.Client.Apply()")
	}

	return id, nil
}

// UpdateSessionActivity updates the session activity column with the current time
func (c *Client) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	_, span := otel.Tracer(name).Start(ctx, "client.UpdateSessionActivity()")
	defer span.End()

	sessionUpdate := struct {
		ID        ccc.UUID  `spanner:"Id"`
		UpdatedAt time.Time `spanner:"UpdatedAt"`
	}{
		ID:        sessionID,
		UpdatedAt: time.Now(),
	}

	mutation, err := spanner.UpdateStruct("Sessions", sessionUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	if _, err := c.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return httpio.NewNotFoundMessagef("session %q not found", sessionUpdate.ID)
		}

		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// DestroySession marks the session as expired
func (c *Client) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	_, span := otel.Tracer(name).Start(ctx, "client.DestroySession()")
	defer span.End()

	sessionUpdate := struct {
		ID        ccc.UUID  `spanner:"Id"`
		Expired   bool      `spanner:"Expired"`
		UpdatedAt time.Time `spanner:"UpdatedAt"`
	}{
		ID:        sessionID,
		Expired:   true,
		UpdatedAt: time.Now(),
	}

	mutation, err := spanner.UpdateStruct("Sessions", sessionUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	if _, err := c.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if !(spanner.ErrCode(err) == codes.NotFound) {
			return errors.Wrap(err, "spanner.Client.Apply()")
		}
	}

	return nil
}

// DestroySessionOIDC marks the session as expired
func (c *Client) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	_, span := otel.Tracer(name).Start(ctx, "client.DestroySessionOIDC()")
	defer span.End()

	_, err := c.spanner.ReadWriteTransaction(ctx, func(_ context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(`
			UPDATE Sessions 
			SET Expired = TRUE, UpdatedAt = CURRENT_TIMESTAMP()
			WHERE NOT Expired AND Username = (
				SELECT Username
				FROM Sessions
				WHERE OidcSid = @oidcSID
			)
		`)
		stmt.Params["oidcSID"] = oidcSID

		if _, err := txn.Update(ctx, stmt); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction().Update()")
		}

		return nil
	})
	if err != nil {
		if !(spanner.ErrCode(err) == codes.NotFound) {
			return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
		}
	}

	return nil
}
