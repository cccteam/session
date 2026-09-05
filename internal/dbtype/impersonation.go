package dbtype

import (
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/sessioninfo"
)

// Principal kinds as stored in the impersonation table's PrincipalKind column.
const (
	PrincipalKindUser = sessioninfo.PrincipalKindUser
	PrincipalKindRole = sessioninfo.PrincipalKindRole
)

// Impersonation is the impersonation record row shared by the drivers.
// Nullable columns are pointers; a nil Mask is the unrestricted mask.
type Impersonation struct {
	SessionID       ccc.UUID
	ActorUsername   string
	ActorRealm      *string
	SourceSessionID *ccc.UUID
	PrincipalKind   string
	PrincipalUser   *string
	PrincipalRole   *string
	Mask            *string
	Reason          *string
	StartedAt       time.Time
	ExpiresAt       time.Time
	EndedAt         *time.Time
	EndReason       *string
}

// InsertImpersonation is the caller-supplied part of a new impersonation
// record; the driver assigns SessionID and StartedAt.
type InsertImpersonation struct {
	ActorUsername   string
	ActorRealm      *string
	SourceSessionID *ccc.UUID
	PrincipalKind   string
	PrincipalUser   *string
	PrincipalRole   *string
	Mask            *string
	Reason          *string
	ExpiresAt       time.Time
}

// NewInsertImpersonation renders a sessioninfo.Impersonation into its insert
// row. Only the caller-supplied fields are read.
func NewInsertImpersonation(imp *sessioninfo.Impersonation) *InsertImpersonation {
	row := &InsertImpersonation{
		ActorUsername: imp.Actor,
		ActorRealm:    optionalString(imp.ActorRealm),
		Reason:        optionalString(imp.Reason),
		Mask:          MaskColumn(imp.Mask),
		ExpiresAt:     imp.ExpiresAt,
	}
	if imp.SourceSessionID.Valid {
		id := imp.SourceSessionID.UUID
		row.SourceSessionID = &id
	}
	if role, ok := imp.Principal.Role(); ok {
		row.PrincipalKind = PrincipalKindRole
		row.PrincipalRole = optionalString(string(role))
	} else {
		user, _ := imp.Principal.User()
		row.PrincipalKind = PrincipalKindUser
		row.PrincipalUser = optionalString(string(user))
	}

	return row
}

// ToSessionInfo converts the row into the public record.
func (i *Impersonation) ToSessionInfo() *sessioninfo.Impersonation {
	imp := &sessioninfo.Impersonation{
		SessionID:  i.SessionID,
		Actor:      i.ActorUsername,
		ActorRealm: derefString(i.ActorRealm),
		Mask:       MaskFromColumn(i.Mask),
		Reason:     derefString(i.Reason),
		StartedAt:  i.StartedAt,
		ExpiresAt:  i.ExpiresAt,
		EndedAt:    i.EndedAt,
		EndReason:  sessioninfo.ImpersonationEndReason(derefString(i.EndReason)),
	}
	if i.SourceSessionID != nil {
		imp.SourceSessionID = ccc.NullUUID{UUID: *i.SourceSessionID, Valid: true}
	}
	if i.PrincipalKind == PrincipalKindRole {
		imp.Principal = accesstypes.RolePrincipal(accesstypes.Role(derefString(i.PrincipalRole)))
	} else {
		imp.Principal = accesstypes.UserPrincipal(accesstypes.User(derefString(i.PrincipalUser)))
	}

	return imp
}

// MaskColumn renders a mask into its column form: nil for the unrestricted
// mask, otherwise the sorted allowlist joined with commas (the empty string
// for the mask that allows nothing).
func MaskColumn(mask accesstypes.PermissionMask) *string {
	perms := mask.Permissions()
	if perms == nil {
		return nil
	}

	names := make([]string, len(perms))
	for i, perm := range perms {
		names[i] = string(perm)
	}
	col := strings.Join(names, ",")

	return &col
}

// MaskFromColumn parses a mask column: NULL is the unrestricted mask, any
// other value (the empty string included) is a restricted allowlist.
func MaskFromColumn(col *string) accesstypes.PermissionMask {
	if col == nil {
		return accesstypes.PermissionMask{}
	}

	var perms []accesstypes.Permission
	for name := range strings.SplitSeq(*col, ",") {
		if name = strings.TrimSpace(name); name != "" {
			perms = append(perms, accesstypes.Permission(name))
		}
	}

	return accesstypes.MaskPermissions(accesstypes.DenyAll(), perms...)
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}

	return &s
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}
