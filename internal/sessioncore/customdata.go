package sessioncore

import (
	"reflect"

	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// NoCustomData is the custom data type of session types that do not use custom session
// data (the SessionData type parameter) or custom user data (the UserData type
// parameter). Instantiate with NoCustomData for each axis the application does not use.
type NoCustomData struct{}

// EraseMutate adapts a typed mutate callback to the erased form the storage layer
// carries across the driver boundary, guarding the type assertion with a clear error.
func EraseMutate[T any](mutate func(data *T) error) func(data any) error {
	return func(data any) error {
		typed, ok := data.(*T)
		if !ok {
			return errors.Newf("custom data type mismatch: storage decoded %T, session type expects %T", data, (*T)(nil))
		}

		return mutate(typed)
	}
}

// VerifyCustomDataType checks at construction that the storage's attached custom
// session data configuration was built for T. NoCustomData session types skip the
// check (a configuration may still be attached; its data is reachable via
// sessioninfo.CustomDataFromCtx).
func VerifyCustomDataType[T any](storage sessionstorage.BaseStore) error {
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

// VerifyCustomUserDataType checks at construction that the storage's attached custom
// user data configuration was built for U. NoCustomData session types skip the check.
func VerifyCustomUserDataType[U any](storage sessionstorage.BaseStore) error {
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

// VerifyCustomDataTypes checks that the storage's custom session data and custom user
// data configurations were built for S and U.
func VerifyCustomDataTypes[S, U any](storage sessionstorage.BaseStore) error {
	if err := VerifyCustomDataType[S](storage); err != nil {
		return err
	}

	return VerifyCustomUserDataType[U](storage)
}

// VerifyOIDCStorage is the storage check the legacy OIDC type makes at construction.
// The custom data configurations must match S and U, and custom user data needs the
// OIDC user anchor.
func VerifyOIDCStorage[S, U any](storage sessionstorage.BaseStore) error {
	if err := VerifyCustomDataTypes[S, U](storage); err != nil {
		return err
	}
	if storage.CustomUserDataType() != nil && !storage.OIDCUsersEnabled() {
		return errors.New("custom user data on OIDC storage requires the OIDC user anchor: pass sessionstorage.WithOIDCUsers() to the storage constructor")
	}

	return nil
}
