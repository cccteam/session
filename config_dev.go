//go:build insecurecookie

package session

func secureCookie() bool {
	return false
}
