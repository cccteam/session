//go:build !insecurecookie

// Package oidc provides configuration settings for OIDC.
package oidc

func secureCookie() bool {
	return true
}
