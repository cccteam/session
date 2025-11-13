package cookie

// CookieOption defines a function signature for setting cookie client options.
type CookieOption func(*CookieClient)

func (CookieOption) isPreAuthOption()   {}
func (CookieOption) isOIDCAzureOption() {}

// WithCookieName sets the cookie name for the session cookie.
func WithCookieName(name string) CookieOption {
	return CookieOption(func(c *CookieClient) {
		c.cookieName = name
	})
}

// WithCookieDomain sets the domain for the session cookie.
func WithCookieDomain(domain string) CookieOption {
	return CookieOption(func(c *CookieClient) {
		c.domain = domain
	})
}
