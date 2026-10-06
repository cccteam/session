package googlegroups

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
		pages      []page
		status     int
		wantGroups []string
		wantErr    bool
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			var call int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 0 {
					http.Error(w, "boom", tt.status)

					return
				}
				if got := r.URL.Query().Get("userKey"); got != "user@example.com" {
					t.Errorf("userKey = %q, want %q", got, "user@example.com")
				}
				if call > 0 {
					if got := r.URL.Query().Get("pageToken"); got != tt.pages[call-1].nextToken {
						t.Errorf("pageToken = %q, want %q", got, tt.pages[call-1].nextToken)
					}
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

			groups, err := d.UserGroups(ctx, "user@example.com")
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
