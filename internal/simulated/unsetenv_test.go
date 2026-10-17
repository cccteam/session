//go:build skipAuth

package simulated

import (
	"os"

	"github.com/go-playground/errors/v5"
)

// unsetenv removes a variable a case must not see; t.Setenv has already recorded the
// value to restore.
func unsetenv(name string) error {
	if err := os.Unsetenv(name); err != nil {
		return errors.Wrapf(err, "os.Unsetenv(%q)", name)
	}

	return nil
}
