package util

// Exclude returns all elements that exist in source but not exclude
func Exclude[T comparable](source, exclude []T) []T {
	list := make([]T, 0, len(source))
	for _, item := range source {
		if Contains(exclude, item) {
			continue
		}
		list = append(list, item)
	}

	return list
}

func Contains[T comparable](elems []T, v T) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}

	return false
}