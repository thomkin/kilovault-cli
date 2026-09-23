package main

import (
	"strings"
	"testing"
	"time"
)

// unlockOrSkip runs `unlock` for home, skipping the test when the kernel
// keyring isn't usable here, and locks again when the test ends.
func unlockOrSkip(t *testing.T, home string, args ...string) {
	t.Helper()
	_, stderr, err := runCLIHome(t, home, masterEnv(testMasterPW), "", append([]string{"unlock"}, args...)...)
	if err != nil && strings.Contains(stderr, "kernel keyring is not available") {
		t.Skip("kernel keyring unavailable here")
	}
	if err != nil {
		t.Fatalf("unlock failed: %v\n%s", err, stderr)
	}
	t.Cleanup(func() { runCLIHome(t, home, nil, "", "lock") })
}

func TestUnlock_CommandsSkipPasswordUntilLock(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)

	// Before unlock, no password available → fails (stdin is empty).
	if _, _, err := runCLIHome(t, home, nil, "", "credentials", "list"); err == nil {
		t.Fatal("list worked without a password or session")
	}

	unlockOrSkip(t, home)

	stdout, stderr, err := runCLIHome(t, home, nil, "", "credentials", "list")
	if err != nil {
		t.Fatalf("list with session failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Session: unlocked until") {
		t.Errorf("list output:\n%s", stdout)
	}

	// Writes work through the session too.
	if _, stderr, err := runCLIHome(t, home, nil, "", "credentials", "set-secret", "-u", "carol", "--generate"); err != nil {
		t.Fatalf("set-secret with session failed: %v\n%s", err, stderr)
	}

	stdout, _, _ = runCLIHome(t, home, nil, "", "lock")
	if !strings.Contains(stdout, "Locked") {
		t.Errorf("lock output: %q", stdout)
	}
	if _, _, err := runCLIHome(t, home, nil, "", "credentials", "list"); err == nil {
		t.Error("list still worked after lock")
	}
	if stdout, _, _ := runCLIHome(t, home, nil, "", "lock"); !strings.Contains(stdout, "Not unlocked") {
		t.Errorf("second lock output: %q", stdout)
	}
}

func TestUnlock_WrongPasswordCreatesNoSession(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)
	unlockOrSkip(t, home) // proves the keyring works here
	runCLIHome(t, home, nil, "", "lock")

	if _, _, err := runCLIHome(t, home, masterEnv("wrong password here"), "", "unlock"); err == nil {
		t.Fatal("unlock accepted a wrong password")
	}
	if _, _, err := runCLIHome(t, home, nil, "", "credentials", "list"); err == nil {
		t.Error("a session exists after a failed unlock")
	}
}

func TestUnlock_Expires(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)
	unlockOrSkip(t, home, "--timeout", "1s")

	time.Sleep(2100 * time.Millisecond)
	if _, _, err := runCLIHome(t, home, nil, "", "credentials", "list"); err == nil {
		t.Error("session still valid after its timeout")
	}
}

func TestUnlock_RejectsBadTimeout(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)
	for _, timeout := range []string{"0s", "48h"} {
		if _, _, err := runCLIHome(t, home, masterEnv(testMasterPW), "", "unlock", "--timeout", timeout); err == nil {
			t.Errorf("unlock --timeout %s accepted", timeout)
		}
	}
}

func TestPasswd_EndsSession(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)
	unlockOrSkip(t, home)

	newPW := "a brand new master password"
	_, stderr, err := runCLIHome(t, home, nil, newPW+"\n"+newPW+"\n", "credentials", "passwd")
	if err != nil {
		t.Fatalf("passwd via session failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "unlock session was ended") {
		t.Errorf("stderr = %s", stderr)
	}
	if _, _, err := runCLIHome(t, home, nil, "", "credentials", "list"); err == nil {
		t.Error("stale session still opens the store after passwd")
	}
	if _, stderr, err := runCLIHome(t, home, masterEnv(newPW), "", "credentials", "list"); err != nil {
		t.Errorf("new password: %v\n%s", err, stderr)
	}
}
