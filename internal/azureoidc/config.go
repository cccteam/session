//go:build !insecurecookie

package azureoidc

func secureCookie() bool {
	return true
}
