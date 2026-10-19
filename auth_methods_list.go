package session

import (
	"fmt"
	"net/http"

	"github.com/cccteam/httpio"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
)

// MethodList is what an Auth tells its login page (Methods): the sign-in methods the
// page offers, each with the path the application mounted it at, and the pending
// sign-in routes. The application writes it where it wires the routes, so the paths
// the page is told are the paths the router serves.
type MethodList struct {
	// Methods are the methods the page offers, in the order it renders them. Each
	// names a registration on the Auth; a method that is registered but not listed
	// here is not offered.
	Methods []AdvertisedMethod
	// Pending are the paths of the pending sign-in handlers (Pending().Status(),
	// ConfirmWithPassword() and Cancel()), all three or none. The page needs them once a
	// sign-in waits for a confirmation or the application's MFA step.
	Pending PendingRoutes
}

// AdvertisedMethod is one method of a MethodList.
type AdvertisedMethod struct {
	// Name is the name the method was registered under on the Auth ("password", or
	// the application's name for an external registration).
	Name string
	// Label is what the page shows for the method.
	Label string
	// Path is the path the method's Login handler is mounted at, a path in the
	// application in canonical form (see SanitizeReturnURL): /api/user/google/login.
	Path string
}

// PendingRoutes are the paths of the pending sign-in handlers, as a MethodList names
// them.
type PendingRoutes struct {
	Status  string
	Confirm string
	Cancel  string
}

// methodsAnswer is what Methods writes.
type methodsAnswer struct {
	Methods []signin.Advertisement `json:"methods"`
	Pending *pendingAnswer         `json:"pending,omitempty"`
}

// pendingAnswer is the pending block of a methods answer.
type pendingAnswer struct {
	Status  string `json:"status"`
	Confirm string `json:"confirm"`
	Cancel  string `json:"cancel"`
}

// Methods answers the login page with the sign-in methods it offers: for each listed
// method its name, the method behind it, how it starts (a form for the password
// method, a redirect for an external one), its label and its path, in the list's
// order, and the pending sign-in routes when the list names them. The answer is
// public: route it beside the login routes, behind StartSession and before
// ValidateSession, and it needs no XSRF token.
//
//	{"methods": [{"name": "password", "method": "password", "kind": "password", "label": "Password", "path": "/api/user/password/login"},
//	             {"name": "google", "method": "google", "kind": "redirect", "label": "Google", "path": "/api/user/google/login"}],
//	 "pending": {"status": "/api/user/pending", "confirm": "/api/user/pending/confirm", "cancel": "/api/user/pending/cancel"}}
//
// Methods is called where the routes are wired, after every method is registered, and
// panics on a wiring mistake, the way a registration does: an empty list, a method
// that is not registered on this Auth, a name listed twice, a method without a label
// or with a path that is not a canonical path in the application, or a pending block
// with some of its paths.
func (a *Auth[S, U, Tx]) Methods(list *MethodList) http.HandlerFunc {
	answer := a.advertise(list)

	return a.serving(a.baseSession.Handle(func(w http.ResponseWriter, _ *http.Request) error {
		return httpio.NewEncoder(w).Ok(answer)
	}))
}

// advertise builds the methods answer from list, checking each entry against the
// registry under the methods lock without closing registration: the first request
// closes it, as for every handler.
func (a *Auth[S, U, Tx]) advertise(list *MethodList) *methodsAnswer {
	if list == nil || len(list.Methods) == 0 {
		panic("session: Methods is given no sign-in method: list every method the login page offers, each with its label and the path its Login handler is mounted at")
	}

	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	answer := &methodsAnswer{Methods: make([]signin.Advertisement, 0, len(list.Methods))}
	seen := make(map[string]bool, len(list.Methods))
	for _, m := range list.Methods {
		switch {
		case m.Name == "":
			panic("session: Methods lists a sign-in method without a name: name the registration the page offers")
		case !a.methods.registered[m.Name]:
			panic(fmt.Sprintf("session: Methods lists the sign-in method %q, which is not registered on this Auth: register it before the routes are wired, or drop it from the list", m.Name))
		case seen[m.Name]:
			panic(fmt.Sprintf("session: Methods lists the sign-in method %q twice: list each method once", m.Name))
		case m.Label == "":
			panic(fmt.Sprintf("session: Methods lists the sign-in method %q without a label: give it the words the login page shows", m.Name))
		case !advertisedPath(m.Path):
			panic(fmt.Sprintf("session: Methods lists the sign-in method %q at %q, which is not a canonical path in the application: "+
				"give it the path its Login handler is mounted at, such as /api/user/%s/login", m.Name, m.Path, m.Name))
		}
		seen[m.Name] = true

		ad := signin.Advertisement{Name: m.Name, Method: sessioninfo.MethodPassword, Kind: signin.KindPassword, Label: m.Label, Path: m.Path}
		if external, ok := a.methods.external[m.Name]; ok {
			ad.Method, ad.Kind = external.Name, signin.KindRedirect
		}
		answer.Methods = append(answer.Methods, ad)
	}
	answer.Pending = pendingAnswerOf(list.Pending)

	return answer
}

// pendingAnswerOf validates the pending routes: none, or all three as canonical paths.
func pendingAnswerOf(p PendingRoutes) *pendingAnswer {
	if p == (PendingRoutes{}) {
		return nil
	}
	for _, path := range []string{p.Status, p.Confirm, p.Cancel} {
		if !advertisedPath(path) {
			panic(fmt.Sprintf("session: Methods is given the pending routes %+v: name the status, confirm and cancel paths together, each a canonical path in the application, or none", p))
		}
	}

	return &pendingAnswer{Status: p.Status, Confirm: p.Confirm, Cancel: p.Cancel}
}

// advertisedPath reports whether p is a path the page can be sent to: a canonical path
// in the application other than the root.
func advertisedPath(p string) bool {
	return p != "/" && internalcookie.SanitizeReturnURL(p) == p
}
