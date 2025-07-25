package session

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/gorilla/securecookie"
)

func Test_newAuthCookie(t *testing.T) {
	t.Parallel()

	type args struct {
		sameSiteStrict bool
	}
	tests := []struct {
		name    string
		args    args
		sc      *securecookie.SecureCookie
		prepare func(*session)
		wantNil bool
		wantErr bool
	}{
		{
			name:    "error on cookie write",
			sc:      &securecookie.SecureCookie{},
			wantNil: true,
			wantErr: true,
		},
		{
			name: "Success, same site strict",
			args: args{
				sameSiteStrict: true,
			},
			sc: securecookie.New(securecookie.GenerateRandomKey(32), nil),
		},
		{
			name: "Success, not same site strict (None)",
			args: args{
				sameSiteStrict: false,
			},
			sc: securecookie.New(securecookie.GenerateRandomKey(32), nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := &session{cookieManager: &cookieClient{secureCookie: tt.sc, cookiename: string(scAuthCookieName)}}

			w := httptest.NewRecorder()
			got, err := a.newAuthCookie(w, tt.args.sameSiteStrict, ccc.UUID{}, "")
			if (err != nil) != tt.wantErr {
				t.Fatalf("newAuthCookie() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (got == nil) != tt.wantNil {
				t.Errorf("newAuthCookie() = %v, wantNil %v", got, tt.wantNil)
			}
			if got != nil {
				if _, ok := got[scSessionID]; !ok {
					t.Errorf("got[scSessionID] not set. expected it set")
				}
			}

			cookie := w.Header().Get("Set-Cookie")
			t.Logf("Cookie header: %s", cookie)

			if sameSiteStrict := strings.Contains(cookie, "; SameSite=Strict"); sameSiteStrict != tt.args.sameSiteStrict {
				t.Errorf("SameSiteStrict: %v, want SameSiteStrict: %v", sameSiteStrict, tt.args.sameSiteStrict)
			}
		})
	}
}

func Test_readAuthCookie(t *testing.T) {
	t.Parallel()

	sc := securecookie.New(securecookie.GenerateRandomKey(32), nil)
	a := &session{cookieManager: &cookieClient{secureCookie: sc, cookiename: string(scAuthCookieName)}}
	w := httptest.NewRecorder()
	cval := map[scKey]string{
		"key1":           "value1",
		"key2":           "value2",
		scSameSiteStrict: "false",
	}
	if err := a.writeAuthCookie(w, false, cval, ""); err != nil {
		t.Fatalf("writeAuthCookie() err = %v", err)
	}
	// Copy the Cookie over to a new Request
	r := &http.Request{Header: http.Header{"Cookie": w.Header().Values("Set-Cookie")}}

	tests := []struct {
		name    string
		req     *http.Request
		sc      *securecookie.SecureCookie
		prepare func(*session, *http.Request)
		want    map[scKey]string
		want1   bool
	}{
		{
			name:  "success",
			req:   r,
			sc:    sc,
			want:  cval,
			want1: true,
		},
		{
			name: "Fail on cookie",
			req:  &http.Request{},
			sc:   nil,
			want: make(map[scKey]string),
		},
		{
			name: "Fail on decode",
			req:  &http.Request{Header: http.Header{"Cookie": []string{fmt.Sprintf("%s=some-value", scAuthCookieName)}}},
			sc:   &securecookie.SecureCookie{},
			want: make(map[scKey]string),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := &session{cookieManager: &cookieClient{secureCookie: tt.sc, cookiename: string(scAuthCookieName)}}
			got, got1 := app.readAuthCookie(tt.req)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("readAuthCookie() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("readAuthCookie() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_writeAuthCookie(t *testing.T) {
	t.Parallel()
	type appFields struct {
		sc *securecookie.SecureCookie
	}
	tests := []struct {
		name           string
		fields         appFields
		sameSiteStrict bool
		wantWriteErr   bool
	}{
		{
			name:         "Error on Encode",
			fields:       appFields{sc: &securecookie.SecureCookie{}},
			wantWriteErr: true,
		},
		{
			name: "Secure",
			fields: appFields{
				sc: securecookie.New(securecookie.GenerateRandomKey(32), nil),
			},
		},
		{
			name:           "same site strict",
			fields:         appFields{sc: securecookie.New(securecookie.GenerateRandomKey(32), nil)},
			sameSiteStrict: true,
		},
		{
			name:           "not same site strict (None)",
			fields:         appFields{sc: securecookie.New(securecookie.GenerateRandomKey(32), nil)},
			sameSiteStrict: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cval := map[scKey]string{
				"key1": "value1",
				"key2": "value2",
			}
			a := &session{cookieManager: &cookieClient{secureCookie: tt.fields.sc, cookiename: string(scAuthCookieName)}}
			w := httptest.NewRecorder()

			if err := a.writeAuthCookie(w, tt.sameSiteStrict, cval, ""); (err != nil) != tt.wantWriteErr {
				t.Errorf("writeAuthCookie() error = %v, wantErr %v", err, tt.wantWriteErr)
			}
			if tt.wantWriteErr {
				return
			}

			cookie := w.Header().Get("Set-Cookie")
			t.Logf("Cookie header: %s", cookie)

			if secure := strings.Contains(cookie, "; Secure"); secure != secureCookie() {
				t.Errorf("Secure: %v, want Secure: %v", secure, secureCookie())
			}
			if sameSiteStrict := strings.Contains(cookie, "; SameSite=Strict"); sameSiteStrict != tt.sameSiteStrict {
				t.Errorf("SameSiteStrict: %v, want SameSiteStrict: %v", sameSiteStrict, tt.sameSiteStrict)
			}
		})
	}
}
