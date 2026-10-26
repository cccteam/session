//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package deviceflow

import (
	"os"
	"syscall"

	"github.com/go-playground/errors/v5"
)

// lockFile takes an exclusive lock on f, waiting while another process holds it.
func lockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return errors.Wrap(err, "syscall.Flock()")
	}

	return nil
}

// unlockFile releases the lock lockFile took on f.
func unlockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		return errors.Wrap(err, "syscall.Flock()")
	}

	return nil
}
