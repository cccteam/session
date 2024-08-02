package dbx

import "time"

type SessionInfo struct {
	ID        string    `db:"Id"`
	OidcSID   string    `db:"OidcSid"`
	Username  string    `db:"Username"`
	CreatedAt time.Time `db:"CreatedAt"`
	UpdatedAt time.Time `db:"UpdatedAt"`
	Expired   bool      `db:"Expired"`
}
