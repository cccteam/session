package spanner

import "testing"

func TestUsernameIndexFollowsUserTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		table string
		want  string
	}{
		{name: "the default table", table: "SessionUsers", want: "SessionUsersByNormalizedUsername"},
		{name: "a group's own table", table: "PartnerSessionUsers", want: "PartnerSessionUsersByNormalizedUsername"},
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
