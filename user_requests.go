package session

// ChangeSessionUserPasswordRequest takes in the user information for changing a SessionUser password
type ChangeSessionUserPasswordRequest struct {
	OldPassword string
	NewPassword string
}

// CreateUserRequest takes in the user information for creating a new SessionUser. A nil
// Password creates a password-less user. PasswordChangeRequired marks the password as
// one an operator set: the user changes it before anything else is served (see the
// README's "Users and the forced password change"); it needs a Password. Email is
// the address the operator enters, unverified (see "Users and their email address").
type CreateUserRequest struct {
	Username               string  `json:"username"`
	Password               *string `json:"password"`
	Disabled               bool    `json:"disabled"`
	PasswordChangeRequired bool    `json:"passwordChangeRequired"`
	// Email is the user's email address as an operator enters it, unverified: it
	// reserves the address, and a link may be sent to it. Nil for none. When the
	// username is the address (UsernameIsEmail) it is nil or the username.
	Email *string `json:"email"`
}
