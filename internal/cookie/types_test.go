package cookie

import "testing"

// Test_SanitizeReturnURL is the return URL rule (S6, U8): a value is kept only when it is
// a path in this application in its canonical form, so that no redirect helper, proxy or
// browser that normalizes it afterwards can turn it into another host. Anything else
// falls back to "/".
func Test_SanitizeReturnURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		returnURL string
		want      string
	}{
		// Paths in the application are kept byte for byte, with their query and fragment.
		{name: "root passes through", returnURL: "/", want: "/"},
		{name: "local path passes through", returnURL: "/reports", want: "/reports"},
		{name: "nested path with query and fragment passes through", returnURL: "/a/b?x=1#y", want: "/a/b?x=1#y"},
		{name: "local path with query passes through", returnURL: "/reports?year=2026&tab=q3", want: "/reports?year=2026&tab=q3"},
		{name: "an application route with a query passes through", returnURL: "/settings/single-sign-on?test=done", want: "/settings/single-sign-on?test=done"},
		{name: "a fragment passes through", returnURL: "/reports#x", want: "/reports#x"},
		{name: "a trailing slash passes through", returnURL: "/settings/", want: "/settings/"},
		{name: "an encoded slash inside a segment passes through", returnURL: "/files/a%2Fb", want: "/files/a%2Fb"},
		{name: "a query that names another URL is the application's to read", returnURL: "/login?next=%2Fhome&x=a:b@c", want: "/login?next=%2Fhome&x=a:b@c"},

		// Not a path.
		{name: "empty falls back to root", returnURL: "", want: "/"},
		{name: "relative path without leading slash falls back to root", returnURL: "reports", want: "/"},
		{name: "http URL falls back to root", returnURL: "http://evil.com", want: "/"},
		{name: "https URL falls back to root", returnURL: "https://evil.com", want: "/"},
		{name: "whitespace falls back to root", returnURL: "  ", want: "/"},

		// Scheme-relative, directly or once normalized.
		{name: "scheme-relative URL falls back to root", returnURL: "//evil.com", want: "/"},
		{name: "backslash scheme-relative form falls back to root", returnURL: `/\evil.com`, want: "/"},
		{name: "double backslash falls back to root", returnURL: `\\evil.com`, want: "/"},
		{name: "a dot segment before a backslash falls back to root", returnURL: `/./\evil.com`, want: "/"},
		{name: "a dot-dot segment before a backslash falls back to root", returnURL: `/a/../\evil.com`, want: "/"},
		{name: "a dot segment before a double slash falls back to root", returnURL: "/.//evil.com", want: "/"},
		{name: "a dot-dot segment before a double slash falls back to root", returnURL: "/..//evil.com", want: "/"},
		{name: "a backslash mid-path falls back to root", returnURL: `/a\b`, want: "/"},
		{name: "a backslash in the query falls back to root", returnURL: `/a?x=\`, want: "/"},
		{name: "an empty segment mid-path falls back to root", returnURL: "/a//b", want: "/"},
		{name: "a dot segment mid-path falls back to root", returnURL: "/a/./b", want: "/"},
		{name: "a trailing dot-dot segment falls back to root", returnURL: "/a/..", want: "/"},

		// Percent-encoded separators and dot segments.
		{name: "encoded slashes falls back to root", returnURL: "/%2F%2Fevil.com", want: "/"},
		{name: "encoded backslash falls back to root", returnURL: "/%5Cevil.com", want: "/"},
		{name: "lowercase encoded backslash falls back to root", returnURL: "/%5cevil.com", want: "/"},
		{name: "encoded dot segment and backslash falls back to root", returnURL: "/%2e/%5cevil.com", want: "/"},
		{name: "encoded dot-dot segment falls back to root", returnURL: "/a/%2E%2e/b", want: "/"},
		{name: "encoded backslash in the query falls back to root", returnURL: "/a?x=%5c", want: "/"},

		// Control characters, whitespace and characters outside the path's set.
		{name: "a tab falls back to root", returnURL: "/\tevil", want: "/"},
		{name: "a space segment falls back to root", returnURL: "/ /evil.com", want: "/"},
		{name: "a newline falls back to root", returnURL: "/a\nb", want: "/"},
		{name: "a DEL falls back to root", returnURL: "/a\x7fb", want: "/"},
		{name: "encoded CR LF falls back to root", returnURL: "/%0d%0aSet-Cookie:x", want: "/"},
		{name: "a non-ASCII character falls back to root", returnURL: "/café", want: "/"},
		{name: "a fullwidth solidus falls back to root", returnURL: "/／evil.com", want: "/"},
		{name: "a character outside the path set falls back to root", returnURL: "/a<b", want: "/"},
		{name: "unparseable escape falls back to root", returnURL: "/%zz", want: "/"},
		{name: "unparseable escape in the query falls back to root", returnURL: "/a?x=%zz", want: "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := SanitizeReturnURL(tt.returnURL); got != tt.want {
				t.Errorf("SanitizeReturnURL(%q) = %q, want %q", tt.returnURL, got, tt.want)
			}
		})
	}
}
