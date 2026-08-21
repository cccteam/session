package dbtype

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type codecEmbedded struct {
	Inner string `spanner:"Inner" db:"inner"`
}

type codecTestData struct {
	codecEmbedded

	TaggedBoth   string `spanner:"SpannerName" db:"PostgresName"`
	CommaOptions int64  `spanner:"WithOptions,omitempty" db:"with_options,omitempty"`
	Untagged     bool
	Skipped      string `spanner:"-" db:"-"`
	//nolint:unused // exercises the unexported-field skip
	unexported string
}

func TestNewCustomDataCodec_Mapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		structType  reflect.Type
		tagKey      string
		wantColumns []string
		wantErr     bool
	}{
		{
			name:        "spanner tags with embedded promotion, comma cut, untagged fallback, skip markers",
			structType:  reflect.TypeFor[codecTestData](),
			tagKey:      SpannerTagKey,
			wantColumns: []string{"Inner", "SpannerName", "WithOptions", "Untagged"},
		},
		{
			name:        "db tags map independently",
			structType:  reflect.TypeFor[codecTestData](),
			tagKey:      PostgresTagKey,
			wantColumns: []string{"inner", "PostgresName", "with_options", "Untagged"},
		},
		{
			name:       "non-struct type",
			structType: reflect.TypeFor[int](),
			tagKey:     SpannerTagKey,
			wantErr:    true,
		},
		{
			name:       "pointer type",
			structType: reflect.TypeFor[*codecTestData](),
			tagKey:     SpannerTagKey,
			wantErr:    true,
		},
		{
			name: "duplicate columns",
			structType: reflect.TypeFor[struct {
				A string `spanner:"Same"`
				B string `spanner:"Same"`
			}](),
			tagKey:  SpannerTagKey,
			wantErr: true,
		},
		{
			name: "no persistable fields",
			structType: reflect.TypeFor[struct {
				A string `spanner:"-"`
			}](),
			tagKey:  SpannerTagKey,
			wantErr: true,
		},
		{
			name: "embedded pointer struct rejected",
			structType: reflect.TypeFor[struct {
				*codecEmbedded
				A string `spanner:"A"`
			}](),
			tagKey:  SpannerTagKey,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			codec, err := NewCustomDataCodec(tt.structType, tt.tagKey)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewCustomDataCodec() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if diff := cmp.Diff(tt.wantColumns, codec.Columns()); diff != "" {
				t.Errorf("Columns() mismatch (-want +got):\n%s", diff)
			}
			if codec.StructType() != tt.structType {
				t.Errorf("StructType() = %v, want %v", codec.StructType(), tt.structType)
			}
		})
	}
}

func TestCustomDataCodec_ValuesAndFieldAddrs(t *testing.T) {
	t.Parallel()

	codec, err := NewCustomDataCodec(reflect.TypeFor[codecTestData](), SpannerTagKey)
	if err != nil {
		t.Fatalf("NewCustomDataCodec() error = %v", err)
	}

	data, ok := codec.NewStruct().(*codecTestData)
	if !ok {
		t.Fatalf("NewStruct() returned %T, want *codecTestData", codec.NewStruct())
	}

	// Populate through FieldAddrs (simulating a scan), then read back through Values.
	addrs, err := codec.FieldAddrs(data)
	if err != nil {
		t.Fatalf("FieldAddrs() error = %v", err)
	}
	setAddr(t, addrs[0], "inner_v")
	setAddr(t, addrs[1], "tagged_v")
	setAddr(t, addrs[2], int64(42))
	setAddr(t, addrs[3], true)

	values, err := codec.Values(data)
	if err != nil {
		t.Fatalf("Values() error = %v", err)
	}
	want := []any{"inner_v", "tagged_v", int64(42), true}
	if diff := cmp.Diff(want, values); diff != "" {
		t.Errorf("Values() mismatch (-want +got):\n%s", diff)
	}

	// Wrong-type and nil data are errors.
	if _, err := codec.Values(&struct{ X string }{}); err == nil {
		t.Error("Values() with wrong type: expected error")
	}
	if _, err := codec.Values(nil); err == nil {
		t.Error("Values(nil): expected error")
	}
	if _, err := codec.FieldAddrs((*codecTestData)(nil)); err == nil {
		t.Error("FieldAddrs(typed nil): expected error")
	}
}

// setAddr writes v through addr, which must be a *T returned by FieldAddrs.
func setAddr[T any](t *testing.T, addr any, v T) {
	t.Helper()

	p, ok := addr.(*T)
	if !ok {
		t.Fatalf("FieldAddrs() addr is %T, want %T", addr, p)
	}
	*p = v
}
