package signin

import "testing"

func TestAddressDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		email string
		want  string
	}{
		{email: "pat@lakeside.edu", want: "lakeside.edu"},
		{email: "Pat@Lakeside.EDU", want: "lakeside.edu"},
		{email: `"pat@home"@lakeside.edu`, want: "lakeside.edu"},
		{email: "pat", want: ""},
		{email: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			t.Parallel()

			if got := AddressDomain(tt.email); got != tt.want {
				t.Errorf("AddressDomain(%q) = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}
