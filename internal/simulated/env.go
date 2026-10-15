//go:build skipAuth

package simulated

import (
	"os"
	"strings"
)

// The environment variables the simulated sign-in reads: who signs in and the roles
// they hold. A registration reads its own pair first, APP_<NAME>_USERNAME and
// APP_<NAME>_ROLES with the registration's name upper-cased and every character
// outside letters and digits written as an underscore, and the shared pair,
// APP_USERNAME and APP_ROLES, when its own is unset. An application with one
// registration sets the shared pair alone; one with several registrations gives each
// its own person, so two registrations in one process (a console's "google" and a
// portal's "directory") sign in two different people.
const (
	usernameVariable = "APP_USERNAME"
	rolesVariable    = "APP_ROLES"
)

// Username returns who the registration's simulated sign-in signs in.
func Username(registration string) string {
	return lookup(registration, usernameVariable)
}

// Roles returns the roles the registration's simulated sign-in asserts: the
// comma-separated entries of the roles variable, trimmed, empty entries dropped, nil
// when none is set.
func Roles(registration string) []string {
	var roles []string
	for _, role := range strings.Split(lookup(registration, rolesVariable), ",") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		roles = append(roles, role)
	}

	return roles
}

// Variable returns the registration's own name for the shared variable: APP_USERNAME
// becomes APP_<NAME>_USERNAME.
func Variable(registration, shared string) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, registration)

	return "APP_" + name + strings.TrimPrefix(shared, "APP")
}

// lookup reads the registration's own variable, else the shared one.
func lookup(registration, shared string) string {
	if registration != "" {
		if value, ok := os.LookupEnv(Variable(registration, shared)); ok {
			return value
		}
	}

	return os.Getenv(shared)
}
