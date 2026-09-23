package securestore

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnsurePrivateDir creates dir (and parents) with mode 0700 if missing,
// then verifies it: a real directory (not a symlink), owned by the
// current user, with no group/other permissions. Like ssh, it refuses
// rather than silently fixing looser permissions, since those may mean
// the contents were already exposed.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory (symlinks are not allowed here)", dir)
	}
	return checkPrivate(dir, info)
}

// CheckPrivateFile verifies path is a regular file (not a symlink)
// owned by the current user with no group/other permissions.
func CheckPrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (symlinks are not allowed here)", path)
	}
	return checkPrivate(path, info)
}

func checkPrivate(path string, info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		want := os.FileMode(0600)
		if info.IsDir() {
			want = 0700
		}
		return fmt.Errorf("%s has permissions %04o, which allow access by other users; run `chmod %o %s` if that's safe", path, perm, want, path)
	}
	return checkOwner(path, info)
}

// ReadPrivateFile reads path after CheckPrivateFile on it and
// EnsurePrivateDir-style checks on its directory.
func ReadPrivateFile(path string) ([]byte, error) {
	if err := checkPrivateParent(path); err != nil {
		return nil, err
	}
	if err := CheckPrivateFile(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func checkPrivateParent(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory (symlinks are not allowed here)", dir)
	}
	return checkPrivate(dir, info)
}

// WriteFileAtomic writes data to path with mode 0600 inside a private
// (0700) directory: temp file in the same directory, fsync, rename over
// path, fsync the directory. A crash leaves either the old or the new
// file, never a partial one.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := EnsurePrivateDir(dir); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (symlinks are not allowed here)", path)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}

	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
