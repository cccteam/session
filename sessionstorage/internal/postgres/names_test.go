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
			s.SetUserTableName(tt.table)
			if got := s.usernameIndex(); got != tt.want {
				t.Errorf("usernameIndex() = %q, want %q", got, tt.want)
			}
		})
	}
}
