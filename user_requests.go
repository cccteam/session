package session

// ChangeSessionUserPasswordRequest takes in the user information for changing a SessionUser password
type ChangeSessionUserPasswordRequest struct {
	OldPassword string
	NewPassword string
}

// CreateUserRequest takes in the user information for creating a new SessionUser
type CreateUserRequest struct {
	Username string  `json:"username"`
	Password *string `json:"password"`
	Disabled bool    `json:"disabled"`
}
