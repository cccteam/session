package signin

import "github.com/cccteam/session/sessioninfo"

// Kind is how a sign-in method starts, as the login page renders it.
type Kind string

const (
	// KindPassword is a form: the page posts {"username", "password"} to the method's
	// path and reads the password login's JSON answer.
	KindPassword Kind = "password"
	// KindRedirect is a redirect: the page sends the browser to the method's path (a
	// GET, with ?returnUrl= naming the page to come back to), the provider signs the
	// person in, and the method's callback brings the browser back.
	KindRedirect Kind = "redirect"
)

// Advertisement is one registered sign-in method as the Auth lists it to the login
// page (Auth.Methods). The page renders from the list alone: a method that is not
// registered is not listed and has no button, so the browser bundle is the same in
// every environment.
type Advertisement struct {
	// Name is the name the method was registered under on the Auth: "password", or the
	// application's name for an external registration ("google", "lakeside-entra").
	Name string `json:"name"`
	// Method is the method behind the registration (password, azure, google, workos).
	Method sessioninfo.AuthMethod `json:"method"`
	// Kind is how the method starts: a form or a redirect.
	Kind Kind `json:"kind"`
	// Label is what the page shows for the method, the application's wording.
	Label string `json:"label"`
	// Path is where the application mounted the method's Login handler: the form posts
	// to it, the redirect goes to it.
	Path string `json:"path"`
}
