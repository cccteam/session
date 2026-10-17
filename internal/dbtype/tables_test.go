package dbtype

import "testing"

func TestValidateTableName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		table   string
		wantErr bool
	}{
		{name: "a plain identifier", table: "SessionUsers"},
		{name: "an underscore start with digits", table: "_group2_Sessions"},
		{name: "128 characters", table: string(bytesOf('x', 128))},
		{name: "empty", table: "", wantErr: true},
		{name: "a quote", table: `Staff"; DROP TABLE`, wantErr: true},
		{name: "a space", table: "Staff Sessions", wantErr: true},
		{name: "a digit first", table: "2Sessions", wantErr: true},
		{name: "a schema qualifier", table: "public.Sessions", wantErr: true},
		{name: "129 characters", table: string(bytesOf('x', 129)), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateTableName(tt.table); (err != nil) != tt.wantErr {
				t.Errorf("ValidateTableName(%q) error = %v, wantErr %v", tt.table, err, tt.wantErr)
			}
		})
	}
}

// bytesOf is n copies of c.
func bytesOf(c byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}

	return b
}
