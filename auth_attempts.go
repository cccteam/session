package session

import (
	"net"
	"net/http"
	"strings"

	"github.com/cccteam/session/internal/attempts"
)

// clientOf identifies the request's client for the attempt limiter: its address and
// the login's XSRF cookie token, the cookie the XSRF guard reads, which a POST that
// reaches the handler carries. The token is a key, hashed by the limiter; nothing is
// written to the cookie.
func (a *Auth[S, U, Tx]) clientOf(r *http.Request) attempts.Client {
	client := attempts.Client{Address: clientAddress(r)}
	if cookie, err := r.Cookie(a.cookies.XSRFCookieName); err == nil {
		client.Cookie = cookie.Value
	}

	return client
}

// The headers a proxy reports the client's address in.
const (
	trueClientIPHeader = "True-Client-IP"
	realIPHeader       = "X-Real-IP"
	forwardedForHeader = "X-Forwarded-For"
)

// clientAddress is the client's address as the attempt limiter keys it: the address a
// proxy reports in True-Client-IP, X-Real-IP or the first entry of X-Forwarded-For,
// read in that order as chi's RealIP does, else the connection's remote address. The
// address key is a throttle, not a security boundary: the headers are the client's to
// forge, so a forged one picks another key and evades this key alone, while the name's
// lock and the edge's own throttle still hold the client; and behind a proxy that sets
// none of them, every client shares the proxy's address.
func clientAddress(r *http.Request) string {
	for _, header := range []string{trueClientIPHeader, realIPHeader} {
		if addr := strings.TrimSpace(r.Header.Get(header)); addr != "" {
			return addr
		}
	}
	if forwarded := r.Header.Get(forwardedForHeader); forwarded != "" {
		first, _, _ := strings.Cut(forwarded, ",")
		if addr := strings.TrimSpace(first); addr != "" {
			return addr
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}
