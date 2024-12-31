package util

import (
	"reflect"
	"testing"
)

func TestExclude(t *testing.T) {
	t.Parallel()

	type args struct {
		source  []int
		exclude []int
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{
			name: "intersection",
			args: args{
				source:  []int{1, 2, 3, 4},
				exclude: []int{2, 4},
			},
			want: []int{1, 3},
		},
		{
			name: "no intersection",
			args: args{
				source:  []int{1, 2, 3, 4},
				exclude: []int{5, 6},
			},
			want: []int{1, 2, 3, 4},
		},
		{
			name: "complete overlap",
			args: args{
				source:  []int{1, 2},
				exclude: []int{1, 2},
			},
			want: []int{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Exclude(tt.args.source, tt.args.exclude); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Exclude() = %v, want %v", got, tt.want)
			}
		})
	}
}
