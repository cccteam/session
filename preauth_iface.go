package session

var _ PreAuthHandlers = &PreauthSession{}

type PreAuthHandlers interface {
	sessionHandlers
}
