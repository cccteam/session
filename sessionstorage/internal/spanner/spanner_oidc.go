package spanner

import (
	"context"
	"fmt"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// InsertSessionOIDC inserts an OIDC Session into the database and returns its id. It
// honors the request's custom session data semantics: per-call data or a configured
// resolver is written atomically with the session insert; a resolver error aborts the
// insert (see SessionStorageDriver.applySessionInsert).
func (s *SessionStorageDriver) InsertSessionOIDC(ctx context.Context, insertSession *dbtype.InsertOIDCSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.googleOIDC {
		return ccc.NilUUID, errors.New("InsertSessionOIDC called on a Google OIDC storage driver")
	}

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	session := &struct {
		ID ccc.UUID
		*dbtype.InsertOIDCSession
	}{
		ID:                id,
		InsertOIDCSession: insertSession,
	}

	mutation, err := spanner.InsertStruct(s.sessionTableName, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.InsertStruct()")
	}

	if err := s.applySessionInsertOIDC(ctx, id, mutation, req); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}

// InsertSessionGoogleOIDC inserts a Google OIDC Session into the database and returns
// its id. Google issues no sid claim, so the session row carries no OidcSid. It honors
// the request's custom session data semantics exactly like InsertSessionOIDC.
func (s *SessionStorageDriver) InsertSessionGoogleOIDC(ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !s.googleOIDC {
		return ccc.NilUUID, errors.New("InsertSessionGoogleOIDC called on a non-Google OIDC storage driver")
	}

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	session := &struct {
		ID ccc.UUID
		*dbtype.InsertSession
	}{
		ID:            id,
		InsertSession: insertSession,
	}

	mutation, err := spanner.InsertStruct(s.sessionTableName, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.InsertStruct()")
	}

	if err := s.applySessionInsertOIDC(ctx, id, mutation, req); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}

// applySessionInsertOIDC commits an OIDC session-insert mutation. When the OIDCUsers
// anchor is enabled, one read-write transaction upserts the anchor row (populating
// req.UserID), runs the custom user data login hook, and applies the session insert
// with its custom session data semantics (per-call data wins; otherwise a configured
// resolver runs; otherwise the session is inserted alone). Any error aborts the whole
// transaction: no anchor change, no user data, no session. Without the anchor it
// behaves exactly like applySessionInsert.
func (s *SessionStorageDriver) applySessionInsertOIDC(ctx context.Context, id ccc.UUID, sessionMutation *spanner.Mutation, req *sessioninfo.NewSessionRequest) error {
	if !s.oidcUsersEnabled {
		return s.applySessionInsert(ctx, id, []*spanner.Mutation{sessionMutation}, req)
	}

	if req.CustomData != nil && s.customData == nil {
		return errors.New("custom session data provided but no custom session data config is attached")
	}

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		if err := s.upsertAnchor(ctx, txn, req); err != nil {
			return err
		}

		if err := s.applyOIDCUserDataHook(ctx, txn, req); err != nil {
			return err
		}

		if err := txn.BufferWrite([]*spanner.Mutation{sessionMutation}); err != nil {
			return errors.Wrap(err, "txn.BufferWrite()")
		}

		var data any
		switch {
		case req.CustomData != nil:
			data = req.CustomData
		case s.customData != nil && s.customData.Resolver != nil:
			resolved, err := s.customData.Resolver(ctx, txn, req)
			if err != nil {
				return errors.Wrap(err, "CustomSessionDataConfig.Resolver()")
			}
			data = resolved
		}
		if data != nil {
			m, err := s.customDataMutation(id, data, spanner.InsertMap)
			if err != nil {
				return err
			}
			if err := txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
				return errors.Wrap(err, "txn.BufferWrite()")
			}
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// DestroySessionOIDC marks the session as expired using the oidcSID
func (s *SessionStorageDriver) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	_, err := s.spanner.ReadWriteTransaction(ctx, func(_ context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(fmt.Sprintf(`
			UPDATE %[1]s
			SET Expired = TRUE, UpdatedAt = CURRENT_TIMESTAMP()
			WHERE NOT Expired AND Username = (
				SELECT Username
				FROM %[1]s
				WHERE OidcSid = @oidcSID
			)
		`, s.sessionTableName))
		stmt.Params["oidcSID"] = oidcSID

		if _, err := txn.Update(ctx, stmt); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}
