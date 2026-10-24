package session

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cccteam/ccc/tracer"
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
	// ChangePassword is the path of the password method's ChangeUserPassword handler,
	// which the page needs when a sign-in finds the user must change a password an
	// operator set. It is required when the password method is listed, since every
	// user an operator gives a password must change it, and refused when it is not.
	ChangePassword string
	// Invitation are the paths of the invitation handlers (Invitation().Open(),
	// Accept() and SignUp()), or none. Open and Accept go together; SignUp is named
	// when the password method is listed and refused when it is not.
	Invitation InvitationRoutes
	// Email are the paths of the email address handlers (Email().Add() and Verify()),
	// both or none.
	Email EmailRoutes
	// SignUp are the paths of the sign-up handlers (SignUp().Start(), Open() and
	// Complete()), all three or none; they need the password method listed and
	// registered with OpenSignUp.
	SignUp SignUpRoutes
}

// InvitationRoutes are the paths of the invitation handlers, as a MethodList names
// them.
type InvitationRoutes struct {
	Open   string
	Accept string
	SignUp string
}

// EmailRoutes are the paths of the email address handlers, as a MethodList names them.
type EmailRoutes struct {
	Add    string
	Verify string
}

// SignUpRoutes are the paths of the sign-up handlers, as a MethodList names them.
type SignUpRoutes struct {
	Start    string
	Open     string
	Complete string
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
	Methods        []signin.Advertisement `json:"methods"`
	Pending        *pendingAnswer         `json:"pending,omitempty"`
	ChangePassword string                 `json:"changePassword,omitempty"`
	// UsernameIsEmail says the password method's username is the email address, so
	// the page asks for the address.
	UsernameIsEmail bool              `json:"usernameIsEmail,omitempty"`
	Invitation      *invitationAnswer `json:"invitation,omitempty"`
	Email           *emailAnswer      `json:"email,omitempty"`
	SignUp          *signUpAnswer     `json:"signUp,omitempty"`
}

// invitationAnswer is the invitation block of a methods answer.
type invitationAnswer struct {
	Open   string `json:"open"`
	Accept string `json:"accept"`
	SignUp string `json:"signUp,omitempty"`
	// Standing is the live invitation the browser carries, absent when it carries
	// none or its link is dead.
	Standing *standingInvitationAnswer `json:"standing,omitempty"`
}

// standingInvitationAnswer is the invitation the browser carries, as the invitation
// block of a methods answer reports it: what Invitation().Open() answered when the
// page opened it, less what the block already says.
type standingInvitationAnswer struct {
	Email           string    `json:"email"`
	Tenant          string    `json:"tenant"`
	ExpiresAt       time.Time `json:"expiresAt"`
	UsernameIsEmail bool      `json:"usernameIsEmail"`
}

// emailAnswer is the email block of a methods answer.
type emailAnswer struct {
	Add    string `json:"add"`
	Verify string `json:"verify"`
}

// signUpAnswer is the sign-up block of a methods answer.
type signUpAnswer struct {
	Start    string `json:"start"`
	Open     string `json:"open"`
	Complete string `json:"complete"`
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
// order, the pending sign-in routes when the list names them, and the password
// change route when the password method is listed. When the list names the invitation
// routes and the browser carries a live invitation (the cookie Invitation().Open()
// set), the invitation block also reports it under "standing": the address it was
// sent to, its tenant, when it stops being accepted and whether an account created
// from it takes the address as its username, so a page that arrives without the
// mailed link's token, as it does when an external sign-in was refused and sent it
// back, still shows the invitation. A browser without the cookie, or whose invitation
// is no longer live, gets the block without it. The answer is public: route it beside
// the login routes, behind StartSession and before ValidateSession, and it needs no
// XSRF token.
//
//	{"methods": [{"name": "password", "method": "password", "kind": "password", "label": "Password", "path": "/api/user/password/login"},
//	             {"name": "google", "method": "google", "kind": "redirect", "label": "Google", "path": "/api/user/google/login"}],
//	 "pending": {"status": "/api/user/pending", "confirm": "/api/user/pending/confirm", "cancel": "/api/user/pending/cancel"},
//	 "changePassword": "/api/user/password",
//	 "invitation": {"open": "/api/user/invitation", "accept": "/api/user/invitation/accept", "signUp": "/api/user/invitation/sign-up",
//	                "standing": {"email": "pat@lakeside.edu", "tenant": "", "expiresAt": "2026-10-31T20:00:00Z", "usernameIsEmail": false}}}
//
// Methods is called where the routes are wired, after every method is registered, and
// panics on a wiring mistake, the way a registration does: an empty list, a method
// that is not registered on this Auth, a name listed twice, a method without a label
// or with a path that is not a canonical path in the application, a pending block
// with some of its paths, the password method without the password change route, or
// that route without the password method.
func (a *Auth[S, U, Tx]) Methods(list *MethodList) http.HandlerFunc {
	answer := a.advertise(list)

	return a.serving(a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		if answer.Invitation == nil {
			return httpio.NewEncoder(w).Ok(answer)
		}

		ctx, span := tracer.Start(r.Context())
		defer span.End()

		standing, err := a.standingInvitation(ctx, r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(answer.withStanding(standing))
	}))
}

// standingInvitation is the live invitation the browser carries, for the invitation
// block of the methods answer: the cookie Invitation().Open() set, read as the sign-in
// handlers read it, and the store asked whether its link still stands. It is nil when
// the browser carries no cookie and when the link is dead (expired, accepted or
// revoked). usernameIsEmail is what Open() answers for the same invitation.
func (a *Auth[S, U, Tx]) standingInvitation(ctx context.Context, r *http.Request) (*standingInvitationAnswer, error) {
	if _, ok := invitationTokenHash(ctx); !ok {
		// StartSession reads the cookie onto the context; a listing routed without it
		// reads the cookie here.
		ctx = a.withInvitationCookie(ctx, r)
	}
	inv, err := a.invitationOf(ctx)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, nil
	}

	return &standingInvitationAnswer{Email: inv.Email, Tenant: inv.Tenant, ExpiresAt: inv.ExpiresAt, UsernameIsEmail: a.registered().usernameIsEmail()}, nil
}

// withStanding is the answer with standing reported in its invitation block: the
// answer itself when there is nothing to report, otherwise a copy, since the answer
// built at wiring is shared by every request.
func (m *methodsAnswer) withStanding(standing *standingInvitationAnswer) *methodsAnswer {
	if standing == nil {
		return m
	}
	answer := *m
	invitation := *m.Invitation
	invitation.Standing = standing
	answer.Invitation = &invitation

	return &answer
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
	passwordListed := seen[string(sessioninfo.MethodPassword)]
	answer.Pending = pendingAnswerOf(list.Pending)
	answer.ChangePassword = changePasswordPathOf(list, passwordListed)
	answer.UsernameIsEmail = passwordListed && a.methods.usernameIsEmail()
	answer.Invitation = invitationAnswerOf(list.Invitation, passwordListed)
	answer.Email = emailAnswerOf(list.Email)
	answer.SignUp = signUpAnswerOf(list.SignUp, passwordListed && a.methods.openSignUp())

	return answer
}

// invitationAnswerOf validates the invitation routes: none, or open and accept as
// canonical paths, with sign-up exactly when the password method is listed.
func invitationAnswerOf(p InvitationRoutes, passwordListed bool) *invitationAnswer {
	if p == (InvitationRoutes{}) {
		return nil
	}
	if !advertisedPath(p.Open) || !advertisedPath(p.Accept) {
		panic(fmt.Sprintf("session: Methods is given the invitation routes %+v: name the open and accept paths together, each a canonical path in the application", p))
	}
	switch {
	case passwordListed && !advertisedPath(p.SignUp):
		panic(fmt.Sprintf("session: Methods lists the password method with the invitation sign-up route %q: give it the path Invitation().SignUp() is mounted at, "+
			"which the login page needs for an invited person who creates an account with a password", p.SignUp))
	case !passwordListed && p.SignUp != "":
		panic(fmt.Sprintf("session: Methods is given the invitation sign-up route %q but lists no password method: drop it, or list the method", p.SignUp))
	}

	return &invitationAnswer{Open: p.Open, Accept: p.Accept, SignUp: p.SignUp}
}

// emailAnswerOf validates the email routes: none, or both as canonical paths.
func emailAnswerOf(p EmailRoutes) *emailAnswer {
	if p == (EmailRoutes{}) {
		return nil
	}
	if !advertisedPath(p.Add) || !advertisedPath(p.Verify) {
		panic(fmt.Sprintf("session: Methods is given the email routes %+v: name the add and verify paths together, each a canonical path in the application", p))
	}

	return &emailAnswer{Add: p.Add, Verify: p.Verify}
}

// signUpAnswerOf validates the sign-up routes: none, or all three as canonical paths,
// on a password method that offers sign-up.
func signUpAnswerOf(p SignUpRoutes, offered bool) *signUpAnswer {
	if p == (SignUpRoutes{}) {
		return nil
	}
	if !offered {
		panic(fmt.Sprintf("session: Methods is given the sign-up routes %+v but the listed password method does not offer sign-up: register it with OpenSignUp, or drop the routes", p))
	}
	if !advertisedPath(p.Start) || !advertisedPath(p.Open) || !advertisedPath(p.Complete) {
		panic(fmt.Sprintf("session: Methods is given the sign-up routes %+v: name the start, open and complete paths together, each a canonical path in the application", p))
	}

	return &signUpAnswer{Start: p.Start, Open: p.Open, Complete: p.Complete}
}

// changePasswordPathOf validates the password change route: present and canonical with
// the password method, absent without it.
func changePasswordPathOf(list *MethodList, passwordListed bool) string {
	switch {
	case passwordListed && !advertisedPath(list.ChangePassword):
		panic(fmt.Sprintf("session: Methods lists the password method with the password change route %q: "+
			"give it the path its ChangeUserPassword handler is mounted at, such as /api/user/password, "+
			"which the login page needs when a sign-in finds the user must change their password", list.ChangePassword))
	case !passwordListed && list.ChangePassword != "":
		panic(fmt.Sprintf("session: Methods is given the password change route %q but lists no password method: drop it, or list the method", list.ChangePassword))
	}

	return list.ChangePassword
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
