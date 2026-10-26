//go:build windows

package deviceflow

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/go-playground/errors/v5"
)

// The lock is LockFileEx over the first byte of the file, exclusive and waiting, as
// the kernel offers it.
var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const lockfileExclusiveLock = 0x00000002

// lockFile takes an exclusive lock on f, waiting while another process holds it.
func lockFile(f *os.File) error {
	var overlapped syscall.Overlapped
	ok, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if ok == 0 {
		return errors.Wrap(err, "LockFileEx()")
	}

	return nil
}

// unlockFile releases the lock lockFile took on f.
func unlockFile(f *os.File) error {
	var overlapped syscall.Overlapped
	ok, _, err := procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if ok == 0 {
		return errors.Wrap(err, "UnlockFileEx()")
	}

	return nil
}
