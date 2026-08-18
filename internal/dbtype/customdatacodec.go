package dbtype

import (
	"reflect"
	"strings"

	"github.com/go-playground/errors/v5"
)

// Struct tag keys used to derive custom session data columns per backend.
const (
	SpannerTagKey  = "spanner"
	PostgresTagKey = "db"
)

type customDataField struct {
	column string
	index  []int
}

// CustomDataCodec maps a custom session data struct type T to its database columns,
// derived from struct tags once at construction. It provides the erased operations the
// database drivers need: creating values, extracting column-ordered field values for
// writes, and producing column-ordered field addresses for scans.
type CustomDataCodec struct {
	structType reflect.Type
	fields     []customDataField
}

// NewCustomDataCodec builds a codec for structType using the given struct tag key
// ("spanner" or "db"). structType must be a non-pointer struct type. Columns are taken
// from the tag (comma options stripped); untagged exported fields use the field name;
// a tag of "-" skips the field. Duplicate columns, embedded pointer structs, and types
// with no persistable fields are errors.
func NewCustomDataCodec(structType reflect.Type, tagKey string) (*CustomDataCodec, error) {
	if structType == nil || structType.Kind() != reflect.Struct {
		return nil, errors.Newf("custom session data type must be a struct, received %v", structType)
	}

	seen := make(map[string]struct{})
	var fields []customDataField
	for _, field := range reflect.VisibleFields(structType) {
		if field.Anonymous {
			// Check embeds before the exported-name check: an embedded unexported
			// TYPE still promotes exported leaves, and a nil embedded pointer would
			// panic on field traversal.
			if field.Type.Kind() == reflect.Pointer {
				return nil, errors.Newf("embedded pointer field %s is not supported in custom session data types", field.Name)
			}
			if field.Type.Kind() == reflect.Struct {
				// Container only; its promoted leaves are visited by VisibleFields.
				continue
			}
		}
		if !field.IsExported() {
			continue
		}

		column := field.Tag.Get(tagKey)
		if before, _, found := strings.Cut(column, ","); found {
			column = before
		}
		if column == "-" {
			continue
		}
		if column == "" {
			column = field.Name
		}

		if _, duplicate := seen[column]; duplicate {
			return nil, errors.Newf("column %q is mapped by multiple fields in custom session data type %s", column, structType)
		}
		seen[column] = struct{}{}
		fields = append(fields, customDataField{column: column, index: field.Index})
	}

	if len(fields) == 0 {
		return nil, errors.Newf("custom session data type %s has no persistable fields for tag %q", structType, tagKey)
	}

	return &CustomDataCodec{
		structType: structType,
		fields:     fields,
	}, nil
}

// StructType returns the struct type T the codec was built for.
func (c *CustomDataCodec) StructType() reflect.Type {
	return c.structType
}

// Columns returns the ordered column names (excluding SessionId, which is never mapped).
func (c *CustomDataCodec) Columns() []string {
	columns := make([]string, len(c.fields))
	for i, f := range c.fields {
		columns[i] = f.column
	}

	return columns
}

// NewStruct returns a pointer to a new zero value of the struct type (*T as any).
func (c *CustomDataCodec) NewStruct() any {
	return reflect.New(c.structType).Interface()
}

// Values returns the field values of data (*T) aligned with Columns().
func (c *CustomDataCodec) Values(data any) ([]any, error) {
	v, err := c.structValue(data)
	if err != nil {
		return nil, err
	}

	values := make([]any, len(c.fields))
	for i, f := range c.fields {
		values[i] = v.FieldByIndex(f.index).Interface()
	}

	return values, nil
}

// FieldAddrs returns pointers to the fields of data (*T) aligned with Columns(),
// suitable as positional scan destinations.
func (c *CustomDataCodec) FieldAddrs(data any) ([]any, error) {
	v, err := c.structValue(data)
	if err != nil {
		return nil, err
	}

	addrs := make([]any, len(c.fields))
	for i, f := range c.fields {
		addrs[i] = v.FieldByIndex(f.index).Addr().Interface()
	}

	return addrs, nil
}

func (c *CustomDataCodec) structValue(data any) (reflect.Value, error) {
	if data == nil {
		return reflect.Value{}, errors.Newf("custom session data must be a non-nil *%s", c.structType)
	}
	t := reflect.TypeOf(data)
	if t != reflect.PointerTo(c.structType) {
		return reflect.Value{}, errors.Newf("custom session data type mismatch: want *%s, got %T", c.structType, data)
	}
	v := reflect.ValueOf(data)
	if v.IsNil() {
		return reflect.Value{}, errors.Newf("custom session data must be a non-nil *%s", c.structType)
	}

	return v.Elem(), nil
}
