//go:build !insecurecookie

package cookie

func secureCookie() bool {
	return true
}
