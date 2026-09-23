//go:build linux

package securestore

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func checkOwner(path string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: can't determine owner", path)
	}
	if uid := os.Getuid(); int(st.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, not the current user (uid %d)", path, st.Uid, uid)
	}
	return nil
}

// IsRAMBacked reports whether dir lives on tmpfs or ramfs, i.e. files
// written there never reach persistent storage (short of swap).
func IsRAMBacked(dir string) (bool, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err != nil {
		return false, err
	}
	return fs.Type == unix.TMPFS_MAGIC || fs.Type == unix.RAMFS_MAGIC, nil
}

// HardenProcess disables core dumps and marks the process non-dumpable,
// which also stops other processes of the same user from attaching a
// debugger (ptrace) or reading /proc/<pid>/mem. Call it before any
// secret is loaded into memory.
func HardenProcess() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("failed to disable core dumps: %v", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to mark process non-dumpable: %v", err)
	}
	return nil
}
