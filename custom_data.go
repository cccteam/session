package session

import (
	"reflect"

	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// NoCustomData is the custom session data type of session types that do not use custom
// session data. The released constructors (NewPasswordAuth, NewOIDCAzure, NewPreauth)
// build session types instantiated with NoCustomData.
type NoCustomData struct{}

// eraseMutate adapts a typed mutate callback to the erased form the storage layer
// carries across the driver boundary, guarding the type assertion with a clear error.
func eraseMutate[T any](mutate func(data *T) error) func(data any) error {
	return func(data any) error {
		typed, ok := data.(*T)
		if !ok {
			return errors.Newf("custom session data type mismatch: storage decoded %T, session type expects %T", data, (*T)(nil))
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
