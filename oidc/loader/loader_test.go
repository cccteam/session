// provider contains interfaces for safely accessing an OIDC Provider
package loader

import (
	"reflect"
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()

	type args struct {
		issuerURL    string
		clientID     string
		clientSecret string
		redirectURL  string
	}
	tests := []struct {
		name string
		args args
		want *loader
	}{
		{
			name: "Test New",
			args: args{
				issuerURL:    "https://example.com",
				clientID:     "clientID",
				clientSecret: "clientSecret",
				redirectURL:  "https://example.com/redirect",
			},
			want: &loader{
				issuerURL:    "https://example.com",
				clientID:     "clientID",
				clientSecret: "clientSecret",
				redirectURL:  "https://example.com/redirect",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := New(tt.args.issuerURL, tt.args.clientID, tt.args.clientSecret, tt.args.redirectURL); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvider_SetLoginURL(t *testing.T) {
	t.Parallel()

	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test SetLoginURL",
			args: args{
				url: "/login",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := &loader{}
			p.SetLoginURL(tt.args.url)
			if p.loginURL != tt.args.url {
				t.Errorf("SetLoginURL() = %v, want %v", p.loginURL, tt.args.url)
			}
		})
	}
}

func TestProvider_LoginURL(t *testing.T) {
	t.Parallel()

	type fields struct {
		loginURL string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test LoginURL",
			fields: fields{
				loginURL: "/login2",
			},
			want: "/login2",
		},
		{
			name: "Test default LoginURL",
			want: "/login",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := &loader{
				loginURL: tt.fields.loginURL,
			}
			if got := p.LoginURL(); got != tt.want {
				t.Errorf("Provider.LoginURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
