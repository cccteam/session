package session

type PreAuthHandlers interface { // only including this to avoid having to export the sessionHandlers interface
	sessionHandlers
}
