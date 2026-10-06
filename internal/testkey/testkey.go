// Package testkey holds the one cookie master key the test suites share. It imports
// nothing, so any package's tests can use it, including the cookie package's own.
package testkey

// CookieKey is a base64 master key for the cookie client. It is a test fixture, not a
// secret: the same key in every suite means a cookie minted in one test setup is
// readable in another, which the seam suite relies on.
const CookieKey = "Rsgb6WsDvBsMQ5IJr2WJjVLCPO+o9WW6SdVktdaaq9O0WFA0Hc/EmJeOwCGV6LIqG8ue3iSZ/lycpv8ZNKvWjWU42hZnlO15vYANZG89R1ncjmu4KStldFuP/r0RFhZa"
