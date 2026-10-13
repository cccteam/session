package dbtype

import (
	"regexp"

	"github.com/go-playground/errors/v5"
)

// tableIdentifier is the shape of a table name a store accepts: it is interpolated
// into SQL, so only a plain identifier gets through.
var tableIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,127}$`)

// ValidateTableName refuses a table name that is not a plain identifier: a letter or
// underscore, then up to 127 letters, digits or underscores. Every table-name setter of
// both drivers runs it, so a name reaches SQL validated whichever way it was set.
func ValidateTableName(name string) error {
	if !tableIdentifier.MatchString(name) {
		return errors.Newf("table name %q: a table name starts with a letter or underscore, followed by up to 127 letters, numbers or underscores", name)
	}

	return nil
}
