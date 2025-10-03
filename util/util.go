// Package util is used for general utility function such as generic sorting/filtering and more.
package util

import (
	"slices"
)

// Exclude returns all elements that exist in source but not exclude
func Exclude[T comparable](source, exclude []T) []T {
	list := make([]T, 0, len(source))
	for _, item := range source {
		if slices.Contains(exclude, item) {
			continue
		}
		list = append(list, item)
	}

	return list
}
