package cookie

import (
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/cookie"
)

const (
	// SessionID is the key used to store the SessionID in a Secure Cookie
	SessionID cookie.Key = "sessionID"

	// SameSiteStrict is the key used to store the sameSiteStrict cookie setting
	SameSiteStrict cookie.Key = "sameSiteStrict"

	// OIDCState is the key used to store the state
	OIDCState cookie.Key = "state"
	// Registration is the key under which a registration's state cookie names the
	// registration that wrote it, so a callback completes only the login its own
	// registration began.
	Registration cookie.Key = "registration"

	// OIDCPkceVerifier is the key used to store the PKCE verifier
	OIDCPkceVerifier cookie.Key = "pkceVerifier"

	// ReturnURL is the key used to store the return URL
	ReturnURL cookie.Key = "returnURL"
	// WorkOSOrganization is the key under which a WorkOS login's state cookie carries the
	// organization the login requested, so the callback refuses a profile from another.
	WorkOSOrganization cookie.Key = "organization"
)

const (
	// AuthCookieName is the cookie name of the Secure Cookie
	AuthCookieName = "auth"

	// XSRFCookieName is the cookie name of the XSRF Token Cookie
	XSRFCookieName = "XSRF-TOKEN"

	// OIDCCookieName is the state cookie every OIDC provider shared in v0.12 and earlier.
	// A callback still reads it when the provider's own cookie is absent, so a login
	// started before an upgrade can complete.
	OIDCCookieName = "OIDC"

	// StateCookiePrefix begins the name of a registration's state cookie: the core names
	// the cookie OIDC-<registration> (StateCookieName), so two registrations of one
	// method, and logins with different providers in one browser, never read each
	// other's state. The legacy Azure session keeps OIDC-azure, the name every v0.12
	// Azure login used.
	StateCookiePrefix = "OIDC-"

	// XSRFHeaderName is the header name of the XSRF Token Cookie
	XSRFHeaderName = "X-XSRF-TOKEN"

	// OIDCCookieExpiration is the default expiration for the OIDC Cookie
	OIDCCookieExpiration = 10 * time.Minute
)

// SafeMethods are Idempotent methods as defined by RFC7231 section 4.2.2.
var SafeMethods = methods([]string{"GET", "HEAD", "OPTIONS", "TRACE"})

type methods []string

func (vals methods) Contain(s string) bool {
	return slices.Contains(vals, s)
}

// SanitizeReturnURL constrains a post-login return URL to a path local to the
// application, falling back to "/" for anything else. A value is kept only when it is
// already in canonical form, so no redirect helper, proxy or browser can later normalize
// it into another host. It must start with a single "/", be printable ASCII with no
// backslash (raw or %5C), use only RFC 3986 path characters in its path, and have no
// empty, "." or ".." segment, as written or percent-decoded. The query and fragment
// otherwise pass through. docs/security-invariants.md (S6) lists the full rule.
func SanitizeReturnURL(returnURL string) string {
	if !isLocalPath(returnURL) {
		return "/"
	}

	return returnURL
}

// isLocalPath reports whether s is kept by SanitizeReturnURL.
func isLocalPath(s string) bool {
	if s == "" || s[0] != '/' {
		return false
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return false
	}
	if !hasSafeBytes(s) {
		return false
	}
	p := s
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		p = s[:i]
	}
	if !isSafePath(p) {
		return false
	}
	u, err := url.Parse(s)

	return err == nil && !u.IsAbs() && u.Host == "" && u.Opaque == "" && u.User == nil
}

// hasSafeBytes reports whether s is printable ASCII without a backslash, and every "%"
// in it starts a valid escape that is not an encoded backslash.
func hasSafeBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || c == '\\' {
			return false
		}
		if c != '%' {
			continue
		}
		if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
			return false
		}
		if s[i+1] == '5' && (s[i+2] == 'c' || s[i+2] == 'C') {
			return false
		}
	}

	return true
}

// isSafePath reports whether the path p is made of path characters and is canonical
// both as written and percent-decoded, with no control character once decoded.
func isSafePath(p string) bool {
	for i := 0; i < len(p); i++ {
		if !isPathChar(p[i]) {
			return false
		}
	}
	decoded, err := url.PathUnescape(p)
	if err != nil || !isCanonicalPath(p) || !isCanonicalPath(decoded) {
		return false
	}
	for i := 0; i < len(decoded); i++ {
		if c := decoded[i]; c < ' ' || c == 0x7f || c == '\\' {
			return false
		}
	}

	return true
}

// isCanonicalPath reports whether p, which starts with "/", is unchanged by path.Clean
// but for a trailing slash, and is not scheme-relative.
func isCanonicalPath(p string) bool {
	if p == "/" {
		return true
	}
	if strings.HasPrefix(p, "//") {
		return false
	}
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") {
		clean += "/"
	}

	return clean == p
}

// isPathChar reports whether c is an RFC 3986 pchar or "/".
func isPathChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}

	return strings.IndexByte("-._~!$&'()*+,;=:@%/", c) >= 0
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// RedirectToReturnURL redirects to returnURL once sanitized, through WriteRedirect.
func RedirectToReturnURL(w http.ResponseWriter, returnURL string, code int) {
	WriteRedirect(w, SanitizeReturnURL(returnURL), code)
}

// WriteRedirect answers with code and a Location header of exactly target. It does not
// use http.Redirect, whose path cleaning can turn a local path into a scheme-relative
// URL ("/./\host" becomes "/\host", which browsers read as "//host"). target must be a
// return URL SanitizeReturnURL kept or the application's own configuration.
func WriteRedirect(w http.ResponseWriter, target string, code int) {
	w.Header().Set("Location", target)
	w.WriteHeader(code)
}

// ValidSessionID checks that the sessionID is a valid uuid
func ValidSessionID(sessionID string) (ccc.UUID, bool) {
	sessionUUID, err := ccc.UUIDFromString(sessionID)
	if err != nil {
		return ccc.NilUUID, false
	}

	return sessionUUID, true
}
