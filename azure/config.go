//go:build !insecurecookie

package azure

func secureCookie() bool {
	return true
}
