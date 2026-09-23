//go:build linux

package session

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// Key permission bits (linux/keyctl.h); not exported by x/sys/unix.
const (
	keyPosAll     = 0x3f000000
	keyUsrView    = 0x00010000
	keyUsrRead    = 0x00020000
	keyUsrWrite   = 0x00040000
	keyUsrSearch  = 0x00080000
	keyUsrSetattr = 0x00200000

	// The key is readable by processes of the same uid through the user
	// keyring; other uids get nothing.
	keyPerm = keyPosAll | keyUsrView | keyUsrRead | keyUsrWrite | keyUsrSearch | keyUsrSetattr
)

// mapErr turns "keyring syscalls blocked or missing" (ENOSYS from
// seccomp filters like podman's default, EPERM from Docker's) into
// ErrUnavailable, and adds context to anything else.
func mapErr(step string, err error) error {
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		return ErrUnavailable
	}
	return fmt.Errorf("kernel keyring: %s: %v", step, err)
}

// Save caches key for ttl under id, replacing any existing session.
//
// The key is created in this process's own keyring first: a process
// only fully controls ("possesses") keys it can reach from its own
// keyrings, and whether the per-user keyring is reachable depends on how
// the login was set up (PAM, ssh, containers, ...). Once its permissions
// and timeout are set, it's linked into the user keyring — where later
// commands from any terminal of this user find it — and dropped from the
// process keyring.
func Save(id string, key []byte, ttl time.Duration) (time.Time, error) {
	if err := ValidateTTL(ttl); err != nil {
		return time.Time{}, err
	}
	if _, err := Clear(id); err != nil {
		return time.Time{}, err
	}

	expires := time.Now().Add(ttl).Truncate(time.Second)
	payload := encode(key, expires)
	defer wipe(payload)

	kid, err := unix.AddKey("user", id, payload, unix.KEY_SPEC_PROCESS_KEYRING)
	if err != nil {
		return time.Time{}, mapErr("add key", err)
	}
	fail := func(step string, err error) (time.Time, error) {
		invalidate(kid)
		return time.Time{}, mapErr(step, err)
	}
	if err := unix.KeyctlSetperm(kid, keyPerm); err != nil {
		return fail("set key permissions", err)
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_SET_TIMEOUT, kid, int(ttl.Seconds()), 0, 0); err != nil {
		return fail("set key timeout", err)
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_LINK, kid, unix.KEY_SPEC_USER_KEYRING, 0, 0); err != nil {
		return fail("link key into user keyring", err)
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, kid, unix.KEY_SPEC_PROCESS_KEYRING, 0, 0); err != nil {
		return fail("unlink key from process keyring", err)
	}
	return expires, nil
}

// Load returns the cached session for id, or nil (no error) if there is
// none or it has expired.
func Load(id string) (*Session, error) {
	kid, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, "user", id, 0)
	if err != nil {
		if errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.EKEYEXPIRED) || errors.Is(err, unix.EKEYREVOKED) {
			return nil, nil
		}
		return nil, mapErr("search", err)
	}

	buf := make([]byte, 256)
	defer wipe(buf)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, kid, buf, 0)
	if err != nil {
		if errors.Is(err, unix.EKEYEXPIRED) || errors.Is(err, unix.EKEYREVOKED) {
			return nil, nil
		}
		return nil, mapErr("read key", err)
	}
	if n > len(buf) {
		invalidate(kid)
		return nil, errors.New("malformed session (dropped)")
	}
	s, err := decode(buf[:n])
	if err != nil {
		invalidate(kid)
		return nil, err
	}
	if !time.Now().Before(s.Expires) {
		wipe(s.Key)
		invalidate(kid)
		return nil, nil
	}
	return s, nil
}

// Clear removes the session for id, reporting whether one existed.
func Clear(id string) (bool, error) {
	kid, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, "user", id, 0)
	if err != nil {
		if errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.EKEYEXPIRED) || errors.Is(err, unix.EKEYREVOKED) {
			return false, nil
		}
		return false, mapErr("search", err)
	}
	if err := invalidate(kid); err != nil {
		return false, mapErr("remove key", err)
	}
	return true, nil
}

// invalidate destroys the key immediately (falling back to unlinking it
// from the user keyring on kernels without KEYCTL_INVALIDATE).
func invalidate(kid int) error {
	if _, err := unix.KeyctlInt(unix.KEYCTL_INVALIDATE, kid, 0, 0, 0); err == nil {
		return nil
	}
	_, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, kid, unix.KEY_SPEC_USER_KEYRING, 0, 0)
	return err
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
