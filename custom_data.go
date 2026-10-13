package session

import "github.com/cccteam/session/internal/sessioncore"

// NoCustomData is the custom data type of session types that do not use custom session
// data (the SessionData type parameter) or custom user data (the UserData type
// parameter). Instantiate with NoCustomData for each axis the application does not use,
// e.g. session.NewAuth[session.NoCustomData, session.NoCustomData](...).
type NoCustomData = sessioncore.NoCustomData
