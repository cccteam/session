//go:build !insecurecookie

package cookie

func SecureCookie() bool {
	return true
}
