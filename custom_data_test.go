package session

// testData is the custom session data struct used by the root package tests.
type testData struct {
	Tenant string `spanner:"TenantId" db:"TenantId"`
}

type otherTestData struct {
	Partner string `spanner:"PartnerId" db:"PartnerId"`
}
