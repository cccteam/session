package cloudidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// fakeAPI stands in for the Cloud Identity Groups API: parents names the groups each
// member is directly in, served two to a page so paging is exercised; status, when set,
// is answered to every call instead.
type fakeAPI struct {
	parents map[string][]string
	status  int
	token   string
}

var memberRE = regexp.MustCompile(`member_key_id == '([^']*)'`)

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "memberships:searchDirectGroups") {
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)

		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+f.token {
		http.Error(w, "unexpected token "+got, http.StatusUnauthorized)

		return
	}
	if f.status != 0 {
		http.Error(w, `{"error":{"message":"refused"}}`, f.status)

		return
	}
	m := memberRE.FindStringSubmatch(r.URL.Query().Get("query"))
	if m == nil {
		http.Error(w, "no member in query "+r.URL.Query().Get("query"), http.StatusBadRequest)

		return
	}
	groups := f.parents[m[1]]
	start := 0
	if tok := r.URL.Query().Get("pageToken"); tok != "" {
		start, _ = strconv.Atoi(tok)
	}
	end := min(start+2, len(groups))
	type key struct {
		ID string `json:"id"`
	}
	type membership struct {
		GroupKey key `json:"groupKey"`
	}
	resp := struct {
		Memberships   []membership `json:"memberships"`
		NextPageToken string       `json:"nextPageToken,omitempty"`
	}{}
	for _, g := range groups[start:end] {
		resp.Memberships = append(resp.Memberships, membership{GroupKey: key{ID: g}})
	}
	if end < len(groups) {
		resp.NextPageToken = strconv.Itoa(end)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func chain(n int) map[string][]string {
	parents := map[string][]string{"u@example.com": {"g01@example.com"}}
	for i := 1; i < n; i++ {
		parents[fmt.Sprintf("g%02d@example.com", i)] = []string{fmt.Sprintf("g%02d@example.com", i+1)}
	}

	return parents
}

func TestLookup(t *testing.T) {
	t.Parallel()

	const member, token = "u@example.com", "tok"
	tests := []struct {
		name    string
		api     *fakeAPI
		nested  bool
		member  string
		token   string
		want    []string
		wantErr bool
	}{
		{
			name: "direct groups come back lowercased and sorted, across pages",
			api:  &fakeAPI{parents: map[string][]string{member: {"Zed@Example.com", "app-admin@example.com", "mid@example.com"}}},
			want: []string{"app-admin@example.com", "mid@example.com", "zed@example.com"},
		},
		{
			name: "a person in no group gets an empty answer",
			api:  &fakeAPI{parents: map[string][]string{}},
			want: []string{},
		},
		{
			name:   "nested: the groups of the groups count, level by level",
			api:    &fakeAPI{parents: map[string][]string{member: {"a@example.com"}, "a@example.com": {"b@example.com"}, "b@example.com": {"c@example.com"}}},
			nested: true,
			want:   []string{"a@example.com", "b@example.com", "c@example.com"},
		},
		{
			name:   "nested: a group is asked about once, so a cycle ends the climb",
			api:    &fakeAPI{parents: map[string][]string{member: {"a@example.com"}, "a@example.com": {"b@example.com"}, "b@example.com": {"a@example.com"}}},
			nested: true,
			want:   []string{"a@example.com", "b@example.com"},
		},
		{
			name:   "nested: the climb stops after MaxDepth levels",
			api:    &fakeAPI{parents: chain(12)},
			nested: true,
			want: []string{
				"g01@example.com", "g02@example.com", "g03@example.com", "g04@example.com", "g05@example.com",
				"g06@example.com", "g07@example.com", "g08@example.com", "g09@example.com", "g10@example.com",
			},
		},
		{
			name:   "nested: a group the person may not view is absent, and so is everything above it",
			api:    &fakeAPI{parents: map[string][]string{member: {"a@example.com"}, "hidden@example.com": {"top@example.com"}}},
			nested: true,
			want:   []string{"a@example.com"},
		},
		{
			name:    "a refusal fails the direct lookup",
			api:     &fakeAPI{status: http.StatusForbidden},
			wantErr: true,
		},
		{
			name:    "a refusal fails the nested lookup",
			api:     &fakeAPI{status: http.StatusForbidden},
			nested:  true,
			wantErr: true,
		},
		{
			name:    "a server error fails the lookup",
			api:     &fakeAPI{status: http.StatusInternalServerError},
			wantErr: true,
		},
		{
			name:    "a member spelled with a quote is refused before any call",
			api:     &fakeAPI{parents: map[string][]string{}},
			member:  "o'brien@example.com",
			wantErr: true,
		},
		{
			name:    "no token, no lookup",
			api:     &fakeAPI{parents: map[string][]string{}},
			token:   "-",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.api.token = token
			srv := httptest.NewServer(tt.api)
			t.Cleanup(srv.Close)
			l := Lookup{Endpoint: srv.URL + "/"}
			who, tok := member, token
			if tt.member != "" {
				who = tt.member
			}
			if tt.token != "" {
				tok = ""
			}
			var got []string
			var err error
			if tt.nested {
				got, err = l.NestedGroups(context.Background(), tok, who)
			} else {
				got, err = l.DirectGroups(context.Background(), tok, who)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("Lookup error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Lookup mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
