package session

import (
	"reflect"

	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// NoCustomData is the custom data type of session types that do not use custom session
// data (the SessionData type parameter) or custom user data (the UserData type
// parameter). Instantiate with NoCustomData for each axis the application does not use,
// e.g. session.NewPasswordAuth[session.NoCustomData, session.NoCustomData](...).
type NoCustomData struct{}

// eraseMutate adapts a typed mutate callback to the erased form the storage layer
// carries across the driver boundary, guarding the type assertion with a clear error.
func eraseMutate[T any](mutate func(data *T) error) func(data any) error {
	return func(data any) error {
		typed, ok := data.(*T)
		if !ok {
			return errors.Newf("custom data type mismatch: storage decoded %T, session type expects %T", data, (*T)(nil))
		}

		return mutate(typed)
	}
}

// verifyCustomDataType checks at construction that the storage's attached custom
// session data configuration was built for T. NoCustomData session types skip the
// check (a configuration may still be attached; its data is reachable via
// sessioninfo.CustomDataFromCtx).
func verifyCustomDataType[T any](storage sessionstorage.BaseStore) error {
	tType := reflect.TypeFor[T]()
	if tType == reflect.TypeFor[NoCustomData]() {
		return nil
	}

	cfgType := storage.CustomDataType()
	if cfgType == nil {
		return errors.Newf("session type built for custom data type %s, but the storage has no custom session data configuration", tType)
	}
	if cfgType != tType {
		return errors.Newf("session type built for custom data type %s, but the storage configuration was built for %s", tType, cfgType)
	}

	return nil
}

// verifyCustomUserDataType checks at construction that the storage's attached custom
// user data configuration was built for U. NoCustomData session types skip the check.
func verifyCustomUserDataType[U any](storage sessionstorage.BaseStore) error {
	uType := reflect.TypeFor[U]()
	if uType == reflect.TypeFor[NoCustomData]() {
		return nil
	}

	cfgType := storage.CustomUserDataType()
	if cfgType == nil {
		return errors.Newf("session type built for custom user data type %s, but the storage has no custom user data configuration", uType)
	}
	if cfgType != uType {
		return errors.Newf("session type built for custom user data type %s, but the storage configuration was built for %s", uType, cfgType)
	}

	return nil
}
