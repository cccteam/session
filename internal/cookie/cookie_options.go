package cookie

// Option defines a function signature for setting cookie client options.
type Option func(*CookieClient)

func (Option) isPreAuthOption()   {}
func (Option) isOIDCAzureOption() {}

// WithCookieName sets the cookie name for the session cookie.
func WithCookieName(name string) Option {
	return Option(func(c *CookieClient) {
		c.cookieName = name
	})
}

// WithCookieDomain sets the domain for the session cookie.
func WithCookieDomain(domain string) Option {
	return Option(func(c *CookieClient) {
		c.domain = domain
	})
}
