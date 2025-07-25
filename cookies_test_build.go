//go:build !insecurecookie

package session

// Using this to ensure tests run with secure cookie settings
// In test environment, we want to verify that cookies have the Secure flag set to true
