package cookie

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/types"
	"github.com/gorilla/securecookie"
)

// mockRequestWithXSRFToken Mocks Request with XSRF Token
func mockRequestWithXSRFToken(t *testing.T, method string, sc *securecookie.SecureCookie, setHeader bool, cookieSessionID, requestSessionID ccc.UUID, cookieExpiration time.Duration) *http.Request {
	// Use setXSRFTokenCookie() to generate a valid cookie
	w := httptest.NewRecorder()
	c := CookieClient{
		secureCookie: sc,
	}
	if !c.SetXSRFTokenCookie(w, &http.Request{}, cookieSessionID, cookieExpiration) {
		t.Fatalf("SetXSRFTokenCookie() = false, should have set cookie in request recorder")
	}

	// Create request using cookie set in Response Recorder
	r := &http.Request{
		Method: method,
		Header: http.Header{
			"Cookie": w.Header().Values("Set-Cookie"),
		},
	}

	if setHeader {
		// Get XSRF cookie
		c, err := r.Cookie(types.STCookieName)
		if err != nil {
			return r
		}

		// Set XSRF Token header to XSRF cookie value
		r.Header.Set(types.STHeaderName, c.Value)
	}

	// Store sessionID in context
	r = r.WithContext(context.WithValue(context.Background(), types.CTXSessionID, requestSessionID))

	return r
}

func Test_newAuthCookie(t *testing.T) {
	t.Parallel()

	type args struct {
		sameSiteStrict bool
	}
	tests := []struct {
		name    string
		args    args
		sc      *securecookie.SecureCookie
		prepare func(*CookieClient)
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
			a := &CookieClient{secureCookie: tt.sc, cookieName: string(types.SCAuthCookieName)}

			w := httptest.NewRecorder()
			got, err := a.NewAuthCookie(w, tt.args.sameSiteStrict, ccc.UUID{})
			if (err != nil) != tt.wantErr {
				t.Fatalf("newAuthCookie() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (got == nil) != tt.wantNil {
				t.Errorf("newAuthCookie() = %v, wantNil %v", got, tt.wantNil)
			}
			if got != nil {
				if _, ok := got[types.SCSessionID]; !ok {
					t.Errorf("got[types.SCSessionID] not set. expected it set")
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
	a := &CookieClient{secureCookie: sc, cookieName: string(types.SCAuthCookieName)}
	w := httptest.NewRecorder()
	cval := map[types.SCKey]string{
		"key1":                 "value1",
		"key2":                 "value2",
		types.SCSameSiteStrict: "false",
	}
	if err := a.WriteAuthCookie(w, false, cval); err != nil {
		t.Fatalf("WriteAuthCookie() err = %v", err)
	}
	// Copy the Cookie over to a new Request
	r := &http.Request{Header: http.Header{"Cookie": w.Header().Values("Set-Cookie")}}

	tests := []struct {
		name    string
		req     *http.Request
		sc      *securecookie.SecureCookie
		prepare func(*CookieClient, *http.Request)
		want    map[types.SCKey]string
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
			want: make(map[types.SCKey]string),
		},
		{
			name: "Fail on decode",
			req:  &http.Request{Header: http.Header{"Cookie": []string{fmt.Sprintf("%s=some-value", types.SCAuthCookieName)}}},
			sc:   &securecookie.SecureCookie{},
			want: make(map[types.SCKey]string),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := &CookieClient{secureCookie: tt.sc, cookieName: string(types.SCAuthCookieName)}
			got, got1 := app.ReadAuthCookie(tt.req)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadAuthCookie() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("ReadAuthCookie() got1 = %v, want %v", got1, tt.want1)
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

			cval := map[types.SCKey]string{
				"key1": "value1",
				"key2": "value2",
			}
			a := &CookieClient{secureCookie: tt.fields.sc, cookieName: string(types.SCAuthCookieName)}
			w := httptest.NewRecorder()

			if err := a.WriteAuthCookie(w, tt.sameSiteStrict, cval); (err != nil) != tt.wantWriteErr {
				t.Errorf("WriteAuthCookie() error = %v, wantErr %v", err, tt.wantWriteErr)
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

func Test_setXSRFTokenCookie(t *testing.T) {
	t.Parallel()

	sc := securecookie.New(securecookie.GenerateRandomKey(32), nil)

	type args struct {
		r                *http.Request
		sessionID        ccc.UUID
		cookieExpiration time.Duration
	}
	tests := []struct {
		name         string
		secureCookie *securecookie.SecureCookie
		args         args
		wantSet      bool
	}{
		{
			name:         "set missing cookie",
			secureCookie: sc,
			args: args{
				r:         &http.Request{Method: http.MethodGet},
				sessionID: ccc.NilUUID,
			},
			wantSet: true,
		},
		{
			name:         "found valid cookie",
			secureCookie: sc,
			args: args{
				r:         mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife),
				sessionID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")),
			},
			wantSet: false,
		},
		{
			name:         "xsrf cookie expired, set new cookie",
			secureCookie: sc,
			args: args{
				r:         mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), time.Minute),
				sessionID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")),
			},
			wantSet: true,
		},
		{
			name:         "session does not match, set new cookie",
			secureCookie: sc,
			args: args{
				r:         mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753")), types.XSRFCookieLife),
				sessionID: ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753")),
			},
			wantSet: true,
		},
		{
			name:         "fail to write cookie",
			secureCookie: &securecookie.SecureCookie{},
			args: args{
				r:         &http.Request{Method: http.MethodGet},
				sessionID: ccc.NilUUID,
			},
			wantSet: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			c := &CookieClient{
				secureCookie: tt.secureCookie,
			}
			if gotSet := c.SetXSRFTokenCookie(w, tt.args.r, tt.args.sessionID, tt.args.cookieExpiration); gotSet != tt.wantSet {
				t.Errorf("SetXSRFTokenCookie() = %v, want %v", gotSet, tt.wantSet)
			}
		})
	}
}

func Test_hasValidXSRFToken(t *testing.T) {
	t.Parallel()

	sc := securecookie.New(securecookie.GenerateRandomKey(32), nil)

	tests := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{
			name: "success",
			req:  mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife),
			want: true,
		},
		{
			name: "failure, missing token",
			req:  &http.Request{},
			want: false,
		},
		{
			name: "failure, missing header",
			req:  mockRequestWithXSRFToken(t, http.MethodGet, sc, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife),
			want: false,
		},
		{
			name: "failure, missmatch sessionid",
			req:  mockRequestWithXSRFToken(t, http.MethodGet, sc, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753")), types.XSRFCookieLife),
			want: false,
		},
		{
			name: "failure, expired token",
			req:  mockRequestWithXSRFToken(t, http.MethodGet, sc, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), -time.Minute),
			want: false,
		},
		{
			name: "failure, invalid expiration",
			req: func() *http.Request {
				r := mockRequestWithXSRFToken(t, http.MethodGet, sc, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife)
				r.Header.Set(types.STCookieName, "invalid")
				return r
			}(),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &CookieClient{secureCookie: sc}
			if got := c.HasValidXSRFToken(tt.req); got != tt.want {
				t.Errorf("HasValidXSRFToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_writeXSRFCookie(t *testing.T) {
	t.Parallel()

	type args struct {
		cookieExpiration time.Duration
		cval             map[types.STKey]string
	}
	tests := []struct {
		name         string
		args         args
		secureCookie *securecookie.SecureCookie
		wantErr      bool
	}{
		{
			name: "success",
			args: args{
				cookieExpiration: time.Minute,
				cval:             map[types.STKey]string{types.STKey("key1"): "value1"},
			},
			secureCookie: securecookie.New(securecookie.GenerateRandomKey(32), nil),
		},
		{
			name: "success with secure cookie",
			args: args{
				cookieExpiration: time.Minute,
				cval:             map[types.STKey]string{types.STKey("key1"): "value1"},
			},
			secureCookie: securecookie.New(securecookie.GenerateRandomKey(32), nil),
		},
		{
			name: "failure",
			args: args{
				cookieExpiration: time.Minute,
				cval:             map[types.STKey]string{types.STKey("key1"): "value1"},
			},
			secureCookie: &securecookie.SecureCookie{},
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			c := &CookieClient{
				secureCookie: tt.secureCookie,
			}
			if err := c.WriteXSRFCookie(w, tt.args.cookieExpiration, tt.args.cval); (err != nil) != tt.wantErr {
				t.Errorf("WriteXSRFCookie() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if secure := strings.Contains(w.Header().Get("Set-Cookie"), "; Secure"); secure != secureCookie() {
				t.Errorf("Secure = %v, wantSecure %v", secure, secureCookie())
			}
		})
	}
}

func Test_readXSRFCookie(t *testing.T) {
	t.Parallel()

	sc := securecookie.New(securecookie.GenerateRandomKey(32), nil)

	tests := []struct {
		name          string
		req           *http.Request
		secureCookie  *securecookie.SecureCookie
		wantSessionID string
		wantOK        bool
	}{
		{
			name: "fails to find the cookie",
			req:  &http.Request{},
		},
		{
			name:         "fails to decode the cookie",
			req:          &http.Request{Header: http.Header{"Cookie": []string{fmt.Sprintf("%s=someValue", types.STCookieName)}}},
			secureCookie: sc,
		},
		{
			name:          "success reading the cookie",
			req:           mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753")), types.XSRFCookieLife),
			secureCookie:  sc,
			wantSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5",
			wantOK:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &CookieClient{secureCookie: tt.secureCookie}
			got, gotOK := c.ReadXSRFCookie(tt.req)

			if gotOK != tt.wantOK {
				t.Fatalf("readXSRFCookie() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got[types.STSessionID] != tt.wantSessionID {
				t.Errorf("ReadXSRFCookie() got[stSessionID] = %v, want %v", got, tt.wantSessionID)
			}
			if got[types.STTokenExpiration] == "" {
				t.Errorf("ReadXSRFCookie() got[stTokenExpiration] = %v, want non-empty", got[types.STTokenExpiration])
			}
		})
	}
}

func Test_readXSRFHeader(t *testing.T) {
	t.Parallel()

	sc := securecookie.New(securecookie.GenerateRandomKey(32), nil)

	tests := []struct {
		name          string
		req           *http.Request
		wantSessionID string
		wantOK        bool
	}{
		{
			name: "failure to read xsrf header",
			req:  mockRequestWithXSRFToken(t, http.MethodGet, sc, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife),
		},
		{
			name:          "success reading xsrf header",
			req:           mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife),
			wantSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5",
			wantOK:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &CookieClient{secureCookie: sc}

			got, gotOK := c.ReadXSRFHeader(tt.req)
			if gotOK != tt.wantOK {
				t.Fatalf("ReadXSRFHeader() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got[types.STSessionID] != tt.wantSessionID {
				t.Errorf("ReadXSRFHeader() got[stSessionID] = %v, want %v", got, tt.wantSessionID)
			}
			if got[types.STTokenExpiration] == "" {
				t.Errorf("ReadXSRFHeader() got[stTokenExpiration] = %v, want non-empty", got[types.STTokenExpiration])
			}
		})
	}
}

func Test_write_read_TokenCookie(t *testing.T) {
	t.Parallel()

	type args struct {
		cookieExpiration time.Duration
		cval             map[types.STKey]string
	}
	tests := []struct {
		name         string
		args         args
		secureCookie *securecookie.SecureCookie
		wantErr      bool
	}{
		{
			name: "success",
			args: args{
				cval:             map[types.STKey]string{types.STKey("key1"): "value1"},
				cookieExpiration: time.Minute,
			},
			secureCookie: securecookie.New(securecookie.GenerateRandomKey(32), nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			cookieClient := &CookieClient{secureCookie: tt.secureCookie}
			if err := cookieClient.WriteXSRFCookie(w, tt.args.cookieExpiration, tt.args.cval); (err != nil) != tt.wantErr {
				t.Errorf("WriteXSRFCookie() error = %v, wantErr %v", err, tt.wantErr)
			}
			// Create request using cookie set in Response Recorder
			r := &http.Request{
				Method: http.MethodGet,
				Header: http.Header{
					"Cookie": w.Header().Values("Set-Cookie"),
				},
			}

			// Get XSRF cookie
			c, err := r.Cookie(types.STCookieName)
			if err != nil {
				t.Fatalf("Request.Cookie() = %v", err)
			}

			// Set XSRF Token header to XSRF cookie value
			r.Header.Set(types.STHeaderName, c.Value)

			got, got1 := cookieClient.ReadXSRFCookie(r)
			if !reflect.DeepEqual(got, tt.args.cval) {
				t.Errorf("ReadXSRFCookie() got = %v, want %v", got, tt.args.cval)
			}
			if got1 != true {
				t.Errorf("ReadXSRFCookie() got1 = %v, want %v", got1, true)
			}

			got, got1 = cookieClient.ReadXSRFHeader(r)
			if !reflect.DeepEqual(got, tt.args.cval) {
				t.Errorf("ReadXSRFHeader() got = %v, want %v", got, tt.args.cval)
			}
			if got1 != true {
				t.Errorf("ReadXSRFHeader() got1 = %v, want %v", got1, true)
			}
		})
	}
}
