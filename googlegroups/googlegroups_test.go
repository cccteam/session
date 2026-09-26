//go:build !skipAuth

package googlegroups

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/oauth2"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

func TestNewDirectory_RequiresSubjectWithCredentials(t *testing.T) {
	t.Parallel()

	if _, err := NewDirectory(t.Context(), []byte(`{}`), ""); err == nil {
		t.Error("NewDirectory() error = nil for credentials without subject, want error")
	}
}

func TestDirectory_UserGroups(t *testing.T) {
	t.Parallel()

	type page struct {
		groups    []string
		nextToken string
	}
	tests := []struct {
		name       string
		email      string // the login; user@example.com when empty
		pages      []page
		status     int
		wantGroups []string
		wantErr    bool
		wantNoCall bool // the lookup is refused before any request
	}{
		{
			name:       "single page",
			pages:      []page{{groups: []string{"app-myapp-admin@example.com", "team-eng@example.com"}}},
			wantGroups: []string{"app-myapp-admin@example.com", "team-eng@example.com"},
		},
		{
			name: "pagination is followed",
			pages: []page{
				{groups: []string{"a@example.com"}, nextToken: "page2"},
				{groups: []string{"b@example.com"}},
			},
			wantGroups: []string{"a@example.com", "b@example.com"},
		},
		{
			name:       "group emails are lowercased",
			pages:      []page{{groups: []string{"App-MyApp-Admin@Example.COM"}}},
			wantGroups: []string{"app-myapp-admin@example.com"},
		},
		{
			name:       "no memberships",
			pages:      []page{{}},
			wantGroups: nil,
		},
		{
			name:    "API error propagates",
			status:  http.StatusForbidden,
			wantErr: true,
		},
		{
			name:       "the domain sent is the login's, lowercased",
			email:      "User@Example.COM",
			pages:      []page{{groups: []string{"a@example.com"}}},
			wantGroups: []string{"a@example.com"},
		},
		{
			name:       "an address without a domain is refused before any request",
			email:      "nobody",
			wantErr:    true,
			wantNoCall: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			email := tt.email
			if email == "" {
				email = "user@example.com"
			}

			var call int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.wantNoCall {
					t.Errorf("a request was made for %q, which has no domain", email)
				}
				if tt.status != 0 {
					http.Error(w, "boom", tt.status)

					return
				}
				wantQuery(t, r, "userKey", email)
				// The customer is resolved from the domain: a service account holding an
				// admin role gets "Domain not found" without it.
				wantQuery(t, r, "domain", "example.com")
				if call > 0 {
					wantQuery(t, r, "pageToken", tt.pages[call-1].nextToken)
				}

				p := tt.pages[call]
				call++
				resp := &admin.Groups{NextPageToken: p.nextToken}
				for _, email := range p.groups {
					resp.Groups = append(resp.Groups, &admin.Group{Email: email})
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			}))
			t.Cleanup(server.Close)

			d, err := NewDirectory(ctx, nil, "", option.WithoutAuthentication(), option.WithEndpoint(server.URL))
			if err != nil {
				t.Fatalf("NewDirectory() error = %v", err)
			}

			groups, err := d.UserGroups(ctx, email)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Directory.UserGroups() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(groups) != len(tt.wantGroups) {
				t.Fatalf("Directory.UserGroups() = %v, want %v", groups, tt.wantGroups)
			}
			for i := range groups {
				if groups[i] != tt.wantGroups[i] {
					t.Errorf("Directory.UserGroups()[%d] = %q, want %q", i, groups[i], tt.wantGroups[i])
				}
			}
		})
	}
}

func TestNewDirectory_BuildsTheServiceOnFirstUse(t *testing.T) {
	t.Parallel()

	// One endpoint for every case that reaches the Admin SDK; whether a case does is the
	// case's own business.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&admin.Groups{Groups: []*admin.Group{{Email: "App-MyApp-Admin@Example.COM"}}})
	}))
	t.Cleanup(server.Close)

	tests := []struct {
		name       string
		opts       []option.ClientOption
		callGroups bool
		wantGroups []string
		wantErr    bool
	}{
		{
			// Nothing here authenticates, so the Admin SDK would fall back to Application
			// Default Credentials; construction must not go looking for them. UserGroups is
			// not called: its outcome would depend on the machine.
			name: "no credentials and no options construct without ADC",
		},
		{
			name:       "the service is built on the first UserGroups and answers lowercased groups",
			opts:       []option.ClientOption{option.WithoutAuthentication(), option.WithEndpoint(server.URL)},
			callGroups: true,
			wantGroups: []string{"app-myapp-admin@example.com"},
		},
		{
			// Contradictory credential options are refused by the Admin SDK's own settings
			// validation inside admin.NewService, before any network or filesystem access,
			// so the failure is the same on every machine.
			name: "a credentials problem is deferred to UserGroups and returned again by the next call",
			opts: []option.ClientOption{
				option.WithoutAuthentication(),
				option.WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token"})),
			},
			callGroups: true,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			d, err := NewDirectory(ctx, nil, "", tt.opts...)
			if err != nil {
				t.Fatalf("NewDirectory() error = %v, want nil: construction must not touch the Admin SDK", err)
			}
			if !tt.callGroups {
				return
			}

			first, firstErr := d.UserGroups(ctx, "user@example.com")
			if (firstErr != nil) != tt.wantErr {
				t.Fatalf("Directory.UserGroups() error = %v, wantErr %v", firstErr, tt.wantErr)
			}
			second, secondErr := d.UserGroups(ctx, "user@example.com")
			if tt.wantErr {
				if !errors.Is(secondErr, firstErr) {
					t.Errorf("second Directory.UserGroups() error = %v, want the remembered construction error %v", secondErr, firstErr)
				}

				return
			}
			if secondErr != nil {
				t.Fatalf("second Directory.UserGroups() error = %v", secondErr)
			}
			if diff := cmp.Diff(tt.wantGroups, first); diff != "" {
				t.Errorf("Directory.UserGroups() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(first, second); diff != "" {
				t.Errorf("second Directory.UserGroups() differs from the first (-first +second):\n%s", diff)
			}
		})
	}
}

// wantQuery fails the test when the request's query parameter key is not want.
func wantQuery(t *testing.T, r *http.Request, key, want string) {
	t.Helper()

	if got := r.URL.Query().Get(key); got != want {
		t.Errorf("%s = %q, want %q", key, got, want)
	}
}
