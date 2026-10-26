//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows)

package deviceflow

import "os"

// On a platform without flock or LockFileEx the file lock is a no-op: the refreshes
// of one process are still serialized by the package's mutex, and two processes
// refreshing at once is the risk the person runs there.

// lockFile takes no lock.
func lockFile(*os.File) error {
	return nil
}

// unlockFile releases none.
func unlockFile(*os.File) error {
	return nil
}
