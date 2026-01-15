package cookie

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/types"
)

const cookieKey = "Rsgb6WsDvBsMQ5IJr2WJjVLCPO+o9WW6SdVktdaaq9O0WFA0Hc/EmJeOwCGV6LIqG8ue3iSZ/lycpv8ZNKvWjWU42hZnlO15vYANZG89R1ncjmu4KStldFuP/r0RFhZa"

// mockRequestWithXSRFToken Mocks Request with XSRF Token
func mockRequestWithXSRFToken(t *testing.T, setHeader bool, cookieSessionID, requestSessionID ccc.UUID) *http.Request {
	// Use setXSRFTokenCookie() to generate a valid cookie
	w := httptest.NewRecorder()
	c, err := NewCookieClient(cookieKey)
	if err != nil {
		t.Fatalf("NewCookieClient() error = %v", err)
	}
	if set, _ := c.RefreshXSRFTokenCookie(w, &http.Request{}, cookieSessionID); !set {
		t.Fatalf("SetXSRFTokenCookie() = false, should have set cookie in request recorder")
	}

	// Create request using cookie set in Response Recorder
	r := &http.Request{
		Method: http.MethodGet,
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
		cookieKey      string
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*Client)
		wantNil bool
		wantErr bool
	}{
		{
			name: "error on cookie write",
			args: args{
				cookieKey: "Invalid Key",
			},
			wantNil: true,
			wantErr: true,
		},
		{
			name: "Success, same site strict",
			args: args{
				sameSiteStrict: true,
				cookieKey:      cookieKey,
			},
		},
		{
			name: "Success, not same site strict (None)",
			args: args{
				sameSiteStrict: false,
				cookieKey:      cookieKey,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, err := NewCookieClient(tt.args.cookieKey)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewCookieClient() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			w := httptest.NewRecorder()
			got, err := a.NewAuthCookie(w, tt.args.sameSiteStrict, ccc.UUID{})
			if err != nil {
				t.Fatalf("newAuthCookie() error = %v", err)
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

	a, err := NewCookieClient(cookieKey)
	if err != nil {
		t.Fatalf("NewCookieClient() error = %v", err)
	}
	w := httptest.NewRecorder()
	cval := map[types.SCKey]string{
		"key1":                 "value1",
		"key2":                 "value2",
		types.SCSameSiteStrict: "false",
	}
	if err := a.WriteAuthCookie(w, true, cval); err != nil {
		t.Fatalf("WriteAuthCookie() err = %v", err)
	}
	// Copy the Cookie over to a new Request
	r := &http.Request{Header: http.Header{"Cookie": w.Header().Values("Set-Cookie")}}

	tests := []struct {
		name      string
		req       *http.Request
		prepare   func(*Client, *http.Request)
		want      map[types.SCKey]string
		wantFound bool
		wantErr   bool
	}{
		{
			name:      "success",
			req:       r,
			want:      cval,
			wantFound: true,
		},
		{
			name: "Fail on cookie",
			req:  &http.Request{},
		},
		{
			name:      "Fail on decode",
			req:       &http.Request{Header: http.Header{"Cookie": []string{fmt.Sprintf("%s=some-value", types.SCAuthCookieName)}}},
			wantFound: false,
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app, err := NewCookieClient(cookieKey)
			if err != nil {
				t.Fatalf("NewCookieClient() error = %v", err)
			}
			got, found, err := app.ReadAuthCookie(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReadAuthCookie() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadAuthCookie() got = %v, want %v", got, tt.want)
			}
			if found != tt.wantFound {
				t.Errorf("ReadAuthCookie() got1 = %v, want %v", found, tt.wantFound)
			}
		})
	}
}

func Test_writeAuthCookie(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		sameSiteStrict bool
		cookieKey      string
		wantErr        bool
	}{
		{
			name:      "Error on Encode",
			cookieKey: "Invalid Key",
			wantErr:   true,
		},
		{
			name:      "Secure",
			cookieKey: cookieKey,
		},
		{
			name:           "same site strict",
			sameSiteStrict: true,
			cookieKey:      cookieKey,
		},
		{
			name:           "not same site strict (None)",
			sameSiteStrict: false,
			cookieKey:      cookieKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cval := map[types.SCKey]string{
				"key1": "value1",
				"key2": "value2",
			}
			a, err := NewCookieClient(tt.cookieKey)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewCookieClient() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			w := httptest.NewRecorder()

			if err := a.WriteAuthCookie(w, tt.sameSiteStrict, cval); err != nil {
				t.Errorf("WriteAuthCookie() error = %v", err)
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

func Test_RefreshXSRFTokenCookie(t *testing.T) {
	t.Parallel()

	type args struct {
		r         *http.Request
		sessionID ccc.UUID
		cookieKey string
	}
	tests := []struct {
		name    string
		args    args
		wantSet bool
		wantErr bool
	}{
		{
			name: "set missing cookie",
			args: args{
				r:         &http.Request{Method: http.MethodGet},
				sessionID: ccc.NilUUID,
				cookieKey: cookieKey,
			},
			wantSet: true,
		},
		{
			name: "found valid cookie",
			args: args{
				r:         mockRequestWithXSRFToken(t, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))),
				sessionID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")),
				cookieKey: cookieKey,
			},
			wantSet: false,
		},
		{
			name: "session does not match, set new cookie",
			args: args{
				r:         mockRequestWithXSRFToken(t, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753"))),
				sessionID: ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753")),
				cookieKey: cookieKey,
			},
			wantSet: true,
		},
		{
			name: "fail to write cookie",
			args: args{
				r:         &http.Request{Method: http.MethodGet},
				sessionID: ccc.NilUUID,
				cookieKey: "Invalid Key",
			},
			wantSet: false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			c, err := NewCookieClient(tt.args.cookieKey)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewCookieClient() error = %v", err)
			}
			if tt.wantErr {
				return
			}
			if gotSet, err := c.RefreshXSRFTokenCookie(w, tt.args.r, tt.args.sessionID); gotSet != tt.wantSet {
				t.Errorf("SetXSRFTokenCookie() = %v, want %v", gotSet, tt.wantSet)
			} else if err != nil {
				t.Errorf("SetXSRFTokenCookie() = %v", err)
			}
		})
	}
}

func Test_hasValidXSRFToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     *http.Request
		want    bool
		wantErr bool
	}{
		{
			name: "success",
			req:  mockRequestWithXSRFToken(t, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))),
			want: true,
		},
		{
			name: "failure, missing token",
			req:  &http.Request{},
			want: false,
		},
		{
			name:    "failure, missing header",
			req:     mockRequestWithXSRFToken(t, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))),
			want:    false,
			wantErr: false,
		},
		{
			name: "failure, missmatch sessionid",
			req:  mockRequestWithXSRFToken(t, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753"))),
			want: false,
		},
		{
			name: "failure, invalid expiration",
			req: func() *http.Request {
				r := mockRequestWithXSRFToken(t, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")))
				r.Header.Set(types.STCookieName, "invalid")
				return r
			}(),
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := NewCookieClient(cookieKey)
			if err != nil {
				t.Fatalf("NewCookieClient() error = %v", err)
			}
			if got, err := c.HasValidXSRFToken(tt.req); (err != nil) != tt.wantErr {
				t.Errorf("HasValidXSRFToken() error = %v, wantErr %v", err, tt.wantErr)
			} else if got != tt.want {
				t.Errorf("HasValidXSRFToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_writeXSRFCookie(t *testing.T) {
	t.Parallel()

	type args struct {
		cval      map[types.SCKey]string
		cookieKey string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				cval:      map[types.SCKey]string{types.SCKey("key1"): "value1"},
				cookieKey: cookieKey,
			},
		},
		{
			name: "success with secure cookie",
			args: args{
				cval:      map[types.SCKey]string{types.SCKey("key1"): "value1"},
				cookieKey: cookieKey,
			},
		},
		{
			name: "failure",
			args: args{
				cval:      map[types.SCKey]string{types.SCKey("key1"): "value1"},
				cookieKey: "invalid key",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			c, err := NewCookieClient(tt.args.cookieKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCookieClient() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if err := c.WriteXSRFCookie(w, tt.args.cval); err != nil {
				t.Fatalf("WriteXSRFCookie() error = %v", err)
			}

			if secure := strings.Contains(w.Header().Get("Set-Cookie"), "; Secure"); secure != secureCookie() {
				t.Errorf("Secure = %v, wantSecure %v", secure, secureCookie())
			}
		})
	}
}

func Test_readXSRFCookie(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		req           *http.Request
		wantSessionID string
		wantOK        bool
		wantErr       bool
	}{
		{
			name: "fails to find the cookie",
			req:  &http.Request{},
		},
		{
			name:    "fails to decode the cookie",
			req:     &http.Request{Header: http.Header{"Cookie": []string{fmt.Sprintf("%s=someValue", types.STCookieName)}}},
			wantErr: false,
		},
		{
			name:          "success reading the cookie",
			req:           mockRequestWithXSRFToken(t, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753"))),
			wantSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5",
			wantOK:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := NewCookieClient(cookieKey)
			if err != nil {
				t.Fatalf("NewCookieClient() error = %v", err)
			}
			got, gotOK, err := c.ReadXSRFCookie(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("readXSRFCookie() error = %v, wantErr %v", err, tt.wantErr)
			}

			if gotOK != tt.wantOK {
				t.Fatalf("readXSRFCookie() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got[types.STSessionID] != tt.wantSessionID {
				t.Errorf("ReadXSRFCookie() got[stSessionID] = %v, want %v", got, tt.wantSessionID)
			}
		})
	}
}

func Test_readXSRFHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		req           *http.Request
		wantSessionID string
		wantOK        bool
		wantErr       bool
	}{
		{
			name:    "failure to read xsrf header",
			req:     mockRequestWithXSRFToken(t, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))),
			wantErr: false,
		},
		{
			name:          "success reading xsrf header",
			req:           mockRequestWithXSRFToken(t, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))),
			wantSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5",
			wantOK:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := NewCookieClient(cookieKey)
			if err != nil {
				t.Fatalf("NewCookieClient() error = %v", err)
			}

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
		})
	}
}

func Test_write_read_TokenCookie(t *testing.T) {
	t.Parallel()

	type args struct {
		cval map[types.SCKey]string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				cval: map[types.SCKey]string{types.SCKey("key1"): "value1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			cookieClient, err := NewCookieClient(cookieKey)
			if err != nil {
				t.Fatalf("NewCookieClient() error = %v", err)
			}
			if err := cookieClient.WriteXSRFCookie(w, tt.args.cval); (err != nil) != tt.wantErr {
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

			got, got1, err := cookieClient.ReadXSRFCookie(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadXSRFCookie() error = %v, wantErr %v", err, tt.wantErr)
			}
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
