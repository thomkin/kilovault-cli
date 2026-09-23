//go:build !linux

package securestore

import (
	"errors"
	"os"
)

// The admin store's protections (owner checks, RAM-backed edit dir,
// non-dumpable process) are implemented for Linux only, the platform
// kilovault-cli is released for. Elsewhere they fail closed.

var errUnsupported = errors.New("the encrypted admin store is only supported on Linux")

func checkOwner(path string, info os.FileInfo) error {
	return errUnsupported
}

func IsRAMBacked(dir string) (bool, error) {
	return false, errUnsupported
}

func HardenProcess() error {
	return errUnsupported
}
