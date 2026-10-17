package signin

import (
	"strings"
	"testing"
)

func TestIssuers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		set          Issuers
		contains     []string
		notContained []string
		wantOnly     string
		wantHasOnly  bool
	}{
		{
			name:         "one issuer listed",
			set:          IssuerList("https://login/lakeside"),
			contains:     []string{"https://login/lakeside"},
			notContained: []string{"", "https://login/riverside"},
			wantOnly:     "https://login/lakeside",
			wantHasOnly:  true,
		},
		{
			name:         "several issuers listed, repeats and empties dropped",
			set:          IssuerList("https://login/lakeside", "", "https://login/riverside", "https://login/lakeside"),
			contains:     []string{"https://login/lakeside", "https://login/riverside"},
			notContained: []string{"", "https://login/hilltop"},
		},
		{
			name:         "nothing listed",
			set:          IssuerList(),
			notContained: []string{"", "https://login/lakeside"},
		},
		{
			name:         "a matching rule has no single issuer and never contains an empty string",
			set:          IssuersMatching(func(iss string) bool { return strings.HasPrefix(iss, "https://login/") }),
			contains:     []string{"https://login/lakeside", "https://login/anyone"},
			notContained: []string{"", "https://evil/lakeside"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, iss := range tt.contains {
				if !tt.set.Contains(iss) {
					t.Errorf("Contains(%q) = false, want true", iss)
				}
			}
			for _, iss := range tt.notContained {
				if tt.set.Contains(iss) {
					t.Errorf("Contains(%q) = true, want false", iss)
				}
			}
			if only, ok := tt.set.Only(); only != tt.wantOnly || ok != tt.wantHasOnly {
				t.Errorf("Only() = %q, %v, want %q, %v", only, ok, tt.wantOnly, tt.wantHasOnly)
			}
		})
	}
}
