package postgres

import (
	"context"
	"fmt"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// InsertSessionOIDC inserts an OIDC Session into the database and returns its id. It
// honors the request's custom session data semantics: per-call data or a configured
// resolver is written atomically with the session insert; a resolver error aborts the
// insert (see SessionStorageDriver.execSessionInsert).
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

	query := fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "OidcSid", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5, $6)
		`, s.sessionTableName)
	args := []any{id, insertSession.OidcSID, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired}

	if err := s.execSessionInsertOIDC(ctx, id, query, args, req); err != nil {
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

	query := fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5)
		`, s.sessionTableName)
	args := []any{id, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired}

	if err := s.execSessionInsertOIDC(ctx, id, query, args, req); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}

// execSessionInsertOIDC executes an OIDC session-insert statement. When the OIDCUsers
// anchor is enabled, one transaction upserts the anchor row (populating req.UserID),
// runs the custom user data login hook, and executes the session insert with its custom
// session data semantics (per-call data wins; otherwise a configured resolver runs;
// otherwise the session is inserted alone). Any error aborts the whole transaction: no
// anchor change, no user data, no session. Without the anchor it behaves exactly like
// execSessionInsert.
func (s *SessionStorageDriver) execSessionInsertOIDC(ctx context.Context, id ccc.UUID, query string, args []any, req *sessioninfo.NewSessionRequest) error {
	if !s.oidcUsersEnabled {
		return s.execSessionInsert(ctx, id, query, args, req)
	}

	if req.CustomData != nil && s.customData == nil {
		return errors.New("custom session data provided but no custom session data config is attached")
	}

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	if err := s.upsertAnchor(ctx, txn, req); err != nil {
		return err
	}

	if err := s.applyOIDCUserDataHook(ctx, txn, req); err != nil {
		return err
	}

	if _, err := txn.Exec(ctx, query, args...); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	data := req.CustomData
	if data == nil && s.customData != nil && s.customData.Resolver != nil {
		data, err = s.customData.Resolver(ctx, txn, req)
		if err != nil {
			return errors.Wrap(err, "CustomSessionDataConfig.Resolver()")
		}
	}
	if data != nil {
		if err := s.insertCustomSessionData(ctx, txn, id, data, false); err != nil {
			return err
		}
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "tx.Commit()")
	}

	return nil
}

// DestroySessionOIDC marks the session as expired using the oidcSID
func (s *SessionStorageDriver) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%[1]s" SET "Expired" = TRUE
		WHERE NOT "Expired" AND "Username" = (
			SELECT "Username"
			FROM "%[1]s"
			WHERE "OidcSid" = $1
		)`, s.sessionTableName)

	if _, err := s.conn.Exec(ctx, query, oidcSID); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}
