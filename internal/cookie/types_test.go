package cookie

import "testing"

func Test_SanitizeReturnURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		returnURL string
		want      string
	}{
		{
			name:      "local path passes through",
			returnURL: "/dashboard",
			want:      "/dashboard",
		},
		{
			name:      "local path with query passes through",
			returnURL: "/reports?year=2026&tab=q3",
			want:      "/reports?year=2026&tab=q3",
		},
		{
			name:      "root passes through",
			returnURL: "/",
			want:      "/",
		},
		{
			name:      "empty falls back to root",
			returnURL: "",
			want:      "/",
		},
		{
			name:      "whitespace falls back to root",
			returnURL: "  ",
			want:      "/",
		},
		{
			name:      "absolute URL falls back to root",
			returnURL: "https://evil.example.com/phish",
			want:      "/",
		},
		{
			name:      "scheme-relative URL falls back to root",
			returnURL: "//evil.example.com/phish",
			want:      "/",
		},
		{
			name:      "backslash scheme-relative form falls back to root",
			returnURL: `/\evil.example.com/phish`,
			want:      "/",
		},
		{
			name:      "relative path without leading slash falls back to root",
			returnURL: "dashboard",
			want:      "/",
		},
		{
			name:      "unparseable URL falls back to root",
			returnURL: "/%zz",
			want:      "/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := SanitizeReturnURL(tt.returnURL); got != tt.want {
				t.Errorf("SanitizeReturnURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
