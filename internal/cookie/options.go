package cookie

type cookieOptions struct {
	CookieName     string
	XSRFCookieName string
	XSRFHeaderName string
	Domain         string
}

// Option defines a function signature for setting cookie client options.
type Option func(*cookieOptions)

// WithCookieName sets the cookie name for the session cookie.
func WithCookieName(name string) Option {
	return Option(func(c *cookieOptions) {
		c.CookieName = name
	})
}

// WithCookieDomain sets the domain for the session cookie.
func WithCookieDomain(domain string) Option {
	return Option(func(c *cookieOptions) {
		c.Domain = domain
	})
}

// WithXSRFCookieName sets the cookie name for the XSRF cookie.
func WithXSRFCookieName(name string) Option {
	return Option(func(c *cookieOptions) {
		c.XSRFCookieName = name
	})
}

// WithXSRFHeaderName sets the header name for the XSRF header.
func WithXSRFHeaderName(name string) Option {
	return Option(func(c *cookieOptions) {
		c.XSRFHeaderName = name
	})
}
