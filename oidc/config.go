//go:build !insecurecookie

package oidc

func secureCookie() bool {
	return true
}
