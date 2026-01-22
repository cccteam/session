package cookie

import (
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/go-playground/errors/v5"
)

const (
	// keyPrefix is used to prevent collisions between keys of this package and keys in the underlying paseto.Token.
	// changing this prefix will break all existing cookies (don't do that)
	keyPrefix = "ccc:"
)

type (
	// Key is a type for storing values in a cookie
	Key string
)

// Values holds data to be stored in the cookie
type Values struct {
	token paseto.Token
}

// NewValues returns a new empty token
func NewValues() *Values {
	return &Values{token: paseto.NewToken()}
}

// Get gets the given key and writes the value into output (which should be a a pointer), if present by parsing the JSON using encoding/json.
func (v *Values) Get(key Key, output any) (err error) {
	if err := v.token.Get(keyPrefix+string(key), output); err != nil {
		return errors.Wrap(err, "token.Get()")
	}

	return nil
}

// GetString returns the value for a given key as a string, or error if this is not possible (cannot be a string, or value does not exist)
func (v *Values) GetString(key Key) (string, error) {
	value, err := v.token.GetString(keyPrefix + string(key))
	if err != nil {
		return "", errors.Wrap(err, "token.GetString()")
	}

	return value, nil
}

// GetTime returns the time for a given key as a string, or error if this is not possible (cannot parse as a time, or value does not exist)
func (v *Values) GetTime(key Key) (time.Time, error) {
	t, err := v.token.GetTime(keyPrefix + string(key))
	if err != nil {
		return time.Time{}, errors.Wrap(err, "token.GetTime()")
	}

	return t, nil
}

// Set sets the key with the specified value. Note that this value needs to be serialisable to JSON using encoding/json. Set will check this and return an error if it is not serialisable.
func (v *Values) Set(key Key, value any) error {
	if err := v.token.Set(keyPrefix+string(key), value); err != nil {
		return errors.Wrap(err, "token.Set()")
	}

	return nil
}

// SetString sets the given key with value. If, for some reason, the provided string cannot be serialized as JSON SetString will panic.
func (v *Values) SetString(key Key, value string) *Values {
	v.token.SetString(keyPrefix+string(key), value)

	return v
}

// SetTime sets the given key with the given time, encoded using RFC3339 (the time format used by common PASETO claims).
func (v *Values) SetTime(key Key, value time.Time) *Values {
	v.token.SetTime(keyPrefix+string(key), value)

	return v
}
