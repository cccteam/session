package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
)

// TestSessionStorageDriver_OIDCUsers_LongKey proves the shipped OIDC schema anchors an
// identity whose tid and oid are longer than a GUID: subjects from providers other than
// Entra ID (a WorkOS idp_id reached 40 characters) are not cut off or refused.
func TestSessionStorageDriver_OIDCUsers_LongKey(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	db, err := prepareDatabase(ctx, t, "file://../../../schema/postgresql/oidc/migrations")
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}

	driver := NewSessionStorageDriver(db.Pool)
	driver.EnableOIDCUsers()

	tid := "conn_" + strings.Repeat("t", 59)
	oid := "idp_" + strings.Repeat("o", 60)
	req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "long@example.com", Tid: tid, Oid: oid}
	insert := &dbtype.InsertOIDCSession{
		OidcSID:       "sid-1",
		InsertSession: dbtype.InsertSession{Username: "long@example.com", CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	if _, err := driver.InsertSessionOIDC(ctx, insert, req); err != nil {
		t.Fatalf("InsertSessionOIDC() error = %v", err)
	}

	user, err := driver.OIDCUserByKey(ctx, tid, oid)
	if err != nil {
		t.Fatalf("OIDCUserByKey() error = %v", err)
	}
	if user.Tid != tid || user.Oid != oid || user.ID != req.UserID {
		t.Errorf("OIDCUserByKey() = %+v, want the anchor for the full tid and oid with ID %s", user, req.UserID)
	}
}
