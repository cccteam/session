package session

import (
	"net/url"
	"regexp"
	"testing"
)

// refusalCodeShape is what a refusal code looks like: a token, never a sentence.
var refusalCodeShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// assertRefusalQuery pins the wire contract of a refused login on the redirect the handler
// wrote: the Location's query has exactly the key code, and its value has the shape of a
// code, so no client text and no message key can ride along.
func assertRefusalQuery(t *testing.T, location string) {
	t.Helper()

	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", location, err)
	}
	q := u.Query()
	if len(q) != 1 || !q.Has("code") {
		t.Errorf("refused login Location %q: query keys = %v, want exactly [code]", location, keys(q))
	}
	if code := q.Get("code"); !refusalCodeShape.MatchString(code) {
		t.Errorf("refused login Location %q: code = %q, want a code, not text", location, code)
	}
}

func keys(q url.Values) []string {
	out := make([]string, 0, len(q))
	for k := range q {
		out = append(out, k)
	}

	return out
}
