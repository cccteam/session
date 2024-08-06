package session

import (
	"net/http"
	"strings"

	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
)

// handle returns a handler that logs any error coming from our custom handlers
func (s *session) Handle(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := handler(w, r); err != nil {
			if httpio.CauseIsError(err) {
				logger.Req(r).Error(err)
			} else {
				logger.Req(r).Infof("['%s']", strings.Join(httpio.Messages(err), "', '"))
			}
		}
	})
}
