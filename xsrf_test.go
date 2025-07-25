package session

import (
	context "context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/gorilla/securecookie"
)

// mockRequestWithXSRFToken Mocks Request with XSRF Token
func mockRequestWithXSRFToken(t *testing.T, method string, sc *securecookie.SecureCookie, setHeader bool, cookieSessionID, requestSessionID ccc.UUID, cookieExpiration time.Duration) *http.Request {
	// Use setXSRFTokenCookie() to generate a valid cookie
	w := httptest.NewRecorder()
	c := cookieClient{
		secureCookie: sc,
	}
	if !c.setXSRFTokenCookie(w, &http.Request{}, cookieSessionID, cookieExpiration) {
		t.Fatalf("setXSRFTokenCookie() = false, should have set cookie in request recorder")
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
		c, err := r.Cookie(stCookieName)
		if err != nil {
			return r
		}

		// Set XSRF Token header to XSRF cookie value
		r.Header.Set(stHeaderName, c.Value)
	}

	// Store sessionID in context
	r = r.WithContext(context.WithValue(context.Background(), ctxSessionID, requestSessionID))

	return r
}

func TestAppSetXSRFToken(t *testing.T) {
	t.Parallel()

	type fields struct {
		secureCookie *securecookie.SecureCookie
	}
	type args struct {
		next http.Handler
		r    *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
	}{
		{
			name: "success",
			fields: fields{
				secureCookie: securecookie.New(securecookie.GenerateRandomKey(32), nil),
			},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
				r:    &http.Request{Method: http.MethodGet},
			},
			want: http.StatusAccepted,
		},
		{
			name: "redirect",
			fields: fields{
				secureCookie: securecookie.New(securecookie.GenerateRandomKey(32), nil),
			},
			args: args{
				r: &http.Request{Method: http.MethodPost, URL: &url.URL{}},
			},
			want: http.StatusTemporaryRedirect,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := &session{
				cookieManager: &cookieClient{
					secureCookie: tt.fields.secureCookie,
				},
				handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = err
						}
					}
				},
			}
			w := httptest.NewRecorder()
			a.SetXSRFToken(tt.args.next).ServeHTTP(w, tt.args.r)
			if got := w.Code; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("App.SetXSRFToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAppValidateXSRFToken(t *testing.T) {
	t.Parallel()

	sc := securecookie.New(securecookie.GenerateRandomKey(32), nil)

	type fields struct {
		secureCookie *securecookie.SecureCookie
	}
	type args struct {
		next http.Handler
		r    *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
	}{
		{
			name: "success safe method no cookie",
			fields: fields{
				secureCookie: securecookie.New(securecookie.GenerateRandomKey(32), nil),
			},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
				r:    &http.Request{Method: http.MethodGet},
			},
			want: http.StatusAccepted,
		},
		{
			name:   "success safe method with cookie",
			fields: fields{secureCookie: sc},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
				r:    mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife),
			},
			want: http.StatusAccepted,
		},
		{
			name:   "success non-safe method",
			fields: fields{secureCookie: sc},
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
				r:    mockRequestWithXSRFToken(t, http.MethodPost, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife),
			},
			want: http.StatusAccepted,
		},
		{
			name: "failure non-safe method",
			fields: fields{
				secureCookie: securecookie.New(securecookie.GenerateRandomKey(32), nil),
			},
			args: args{
				r: &http.Request{Method: http.MethodPost},
			},
			want: http.StatusForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := &session{
				cookieManager: &cookieClient{
					secureCookie: tt.fields.secureCookie,
				},
				handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = err
						}
					}
				},
			}
			w := httptest.NewRecorder()
			a.ValidateXSRFToken(tt.args.next).ServeHTTP(w, tt.args.r)
			if got := w.Code; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("App.ValidateXSRFToken() = %v, want %v", got, tt.want)
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
				r:         mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife),
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
				r:         mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753")), xsrfCookieLife),
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
			c := &cookieClient{
				secureCookie: tt.secureCookie,
			}
			if gotSet := c.setXSRFTokenCookie(w, tt.args.r, tt.args.sessionID, tt.args.cookieExpiration); gotSet != tt.wantSet {
				t.Errorf("setXSRFTokenCookie() = %v, want %v", gotSet, tt.wantSet)
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
			req:  mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife),
			want: true,
		},
		{
			name: "failure, missing token",
			req:  &http.Request{},
			want: false,
		},
		{
			name: "failure, missing header",
			req:  mockRequestWithXSRFToken(t, http.MethodGet, sc, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife),
			want: false,
		},
		{
			name: "failure, missmatch sessionid",
			req:  mockRequestWithXSRFToken(t, http.MethodGet, sc, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753")), xsrfCookieLife),
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
				r := mockRequestWithXSRFToken(t, http.MethodGet, sc, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife)
				r.Header.Set(stCookieName, "invalid")
				return r
			}(),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &cookieClient{secureCookie: sc}
			if got := c.hasValidXSRFToken(tt.req); got != tt.want {
				t.Errorf("hasValidXSRFToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_writeXSRFCookie(t *testing.T) {
	t.Parallel()

	type args struct {
		cookieExpiration time.Duration
		cval             map[stKey]string
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
				cval:             map[stKey]string{stKey("key1"): "value1"},
			},
			secureCookie: securecookie.New(securecookie.GenerateRandomKey(32), nil),
		},
		{
			name: "success with secure cookie",
			args: args{
				cookieExpiration: time.Minute,
				cval:             map[stKey]string{stKey("key1"): "value1"},
			},
			secureCookie: securecookie.New(securecookie.GenerateRandomKey(32), nil),
		},
		{
			name: "failure",
			args: args{
				cookieExpiration: time.Minute,
				cval:             map[stKey]string{stKey("key1"): "value1"},
			},
			secureCookie: &securecookie.SecureCookie{},
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			c := &cookieClient{
				secureCookie: tt.secureCookie,
			}
			if err := c.writeXSRFCookie(w, tt.args.cookieExpiration, tt.args.cval); (err != nil) != tt.wantErr {
				t.Errorf("writeXSRFCookie() error = %v, wantErr %v", err, tt.wantErr)
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
			req:          &http.Request{Header: http.Header{"Cookie": []string{fmt.Sprintf("%s=someValue", stCookieName)}}},
			secureCookie: sc,
		},
		{
			name:          "success reading the cookie",
			req:           mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("ba4fdd80-b566-4128-b593-68614e15a753")), xsrfCookieLife),
			secureCookie:  sc,
			wantSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5",
			wantOK:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &cookieClient{secureCookie: tt.secureCookie}
			got, gotOK := c.readXSRFCookie(tt.req)

			if gotOK != tt.wantOK {
				t.Fatalf("readXSRFCookie() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got[stSessionID] != tt.wantSessionID {
				t.Errorf("readXSRFCookie() got[stSessionID] = %v, want %v", got, tt.wantSessionID)
			}
			if got[stTokenExpiration] == "" {
				t.Errorf("readXSRFCookie() got[stTokenExpiration] = %v, want non-empty", got[stTokenExpiration])
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
			req:  mockRequestWithXSRFToken(t, http.MethodGet, sc, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife),
		},
		{
			name:          "success reading xsrf header",
			req:           mockRequestWithXSRFToken(t, http.MethodGet, sc, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife),
			wantSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5",
			wantOK:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &cookieClient{secureCookie: sc}

			got, gotOK := c.readXSRFHeader(tt.req)
			if gotOK != tt.wantOK {
				t.Fatalf("readXSRFHeader() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got[stSessionID] != tt.wantSessionID {
				t.Errorf("readXSRFHeader() got[stSessionID] = %v, want %v", got, tt.wantSessionID)
			}
			if got[stTokenExpiration] == "" {
				t.Errorf("readXSRFHeader() got[stTokenExpiration] = %v, want non-empty", got[stTokenExpiration])
			}
		})
	}
}

func Test_write_read_TokenCookie(t *testing.T) {
	t.Parallel()

	type args struct {
		cookieExpiration time.Duration
		cval             map[stKey]string
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
				cval:             map[stKey]string{stKey("key1"): "value1"},
				cookieExpiration: time.Minute,
			},
			secureCookie: securecookie.New(securecookie.GenerateRandomKey(32), nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			cookieClient := &cookieClient{secureCookie: tt.secureCookie}
			if err := cookieClient.writeXSRFCookie(w, tt.args.cookieExpiration, tt.args.cval); (err != nil) != tt.wantErr {
				t.Errorf("writeXSRFCookie() error = %v, wantErr %v", err, tt.wantErr)
			}
			// Create request using cookie set in Response Recorder
			r := &http.Request{
				Method: http.MethodGet,
				Header: http.Header{
					"Cookie": w.Header().Values("Set-Cookie"),
				},
			}

			// Get XSRF cookie
			c, err := r.Cookie(stCookieName)
			if err != nil {
				t.Fatalf("Request.Cookie() = %v", err)
			}

			// Set XSRF Token header to XSRF cookie value
			r.Header.Set(stHeaderName, c.Value)

			got, got1 := cookieClient.readXSRFCookie(r)
			if !reflect.DeepEqual(got, tt.args.cval) {
				t.Errorf("readXSRFCookie() got = %v, want %v", got, tt.args.cval)
			}
			if got1 != true {
				t.Errorf("readXSRFCookie() got1 = %v, want %v", got1, true)
			}

			got, got1 = cookieClient.readXSRFHeader(r)
			if !reflect.DeepEqual(got, tt.args.cval) {
				t.Errorf("readXSRFHeader() got = %v, want %v", got, tt.args.cval)
			}
			if got1 != true {
				t.Errorf("readXSRFHeader() got1 = %v, want %v", got1, true)
			}
		})
	}
}
