package session

import (
	"time"

	"github.com/cccteam/session/internal/basesession"
)

// BaseSessionOption defines a function signature for setting session options.
type BaseSessionOption func(*basesession.BaseSession)

func (BaseSessionOption) isPreAuthOption()   {}
func (BaseSessionOption) isOIDCAzureOption() {}

// WithLogHandler sets the LogHandler. (default: httpio.Log)
func WithLogHandler(l LogHandler) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.Handle = l
	})
}

var defaultSessionTimeout = time.Minute * 10

// WithSessionTimeout sets the session timeout. (default: 10m)
func WithSessionTimeout(d time.Duration) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.SessionTimeout = d
	})
}
