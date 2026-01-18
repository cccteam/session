package cookie

type (
	// Key is a type for storing values in a cookie
	Key string
)

// Values is a map of cookie values
type Values struct {
	v map[Key]string
}

// NewValues initializes a new Values type
func NewValues() Values {
	return Values{
		v: make(map[Key]string),
	}
}

// Get returns the value of the cookie
func (c Values) Get(key Key) string {
	return c.v[key]
}

// Set sets the value of the cookie
func (c Values) Set(key Key, value string) Values {
	c.v[key] = value

	return c
}

// Delete deletes the value of the cookie
func (c Values) Delete(key Key) Values {
	delete(c.v, key)

	return c
}

// Len returns the number of values set
func (c Values) Len() int {
	return len(c.v)
}

// Has returns wether or not the key exists
func (c Values) Has(key Key) bool {
	_, ok := c.v[key]

	return ok
}
