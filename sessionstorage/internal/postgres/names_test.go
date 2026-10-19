package postgres

import "testing"

func TestUsernameIndexFollowsUserTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		table string
		want  string
	}{
		{name: "the default table", table: "SessionUsers", want: "SessionUsers_NormalizedUsername_idx"},
		{name: "a group's own table", table: "PartnerSessionUsers", want: "PartnerSessionUsers_NormalizedUsername_idx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &SessionStorageDriver{}
			if err := s.SetUserTableName(tt.table); err != nil {
				t.Fatalf("SetUserTableName() error = %v", err)
			}
			if got := s.usernameIndex(); got != tt.want {
				t.Errorf("usernameIndex() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTableNameSettersValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		set  func(s *SessionStorageDriver, name string) error
		get  func(s *SessionStorageDriver) string
	}{
		{name: "SetSessionTableName", set: (*SessionStorageDriver).SetSessionTableName, get: func(s *SessionStorageDriver) string { return s.sessionTableName }},
		{name: "SetUserTableName", set: (*SessionStorageDriver).SetUserTableName, get: func(s *SessionStorageDriver) string { return s.userTableName }},
		{name: "SetOIDCUserTableName", set: (*SessionStorageDriver).SetOIDCUserTableName, get: func(s *SessionStorageDriver) string { return s.oidcUserTableName }},
		{name: "SetIdentitiesTableName", set: (*SessionStorageDriver).SetIdentitiesTableName, get: func(s *SessionStorageDriver) string { return s.identitiesTableName }},
		{name: "SetPendingSignInsTableName", set: (*SessionStorageDriver).SetPendingSignInsTableName, get: func(s *SessionStorageDriver) string { return s.pendingTableName }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := NewSessionStorageDriver(nil)
			before := tt.get(s)
			if err := tt.set(s, `Staff"; DROP TABLE`); err == nil {
				t.Errorf("%s() with a name that is not an identifier error = nil, want a refusal", tt.name)
			}
			if got := tt.get(s); got != before {
				t.Errorf("%s() changed the name to %q on a refusal, want %q kept", tt.name, got, before)
			}
			if err := tt.set(s, "Group_Table2"); err != nil {
				t.Errorf("%s() with an identifier error = %v", tt.name, err)
			}
		})
	}
}
