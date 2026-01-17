//go:build insecurecookie

package cookie

// SecureCookie returns true if the cookie should be secure
func SecureCookie() bool {
	return false
}
