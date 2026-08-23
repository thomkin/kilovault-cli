// Package service installs and enables the systemd unit that runs
// `kilovault fetch` at boot. Linux/systemd-specific: it shells out to
// useradd/groupadd/systemctl since there is no portable Go stdlib
// equivalent for OS user management.
package service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
)

const (
	serviceUser   = "kilovault"
	consumerGroup = "kilovault-consumers"
	homeDir       = "/var/lib/kilovault"
	unitName      = "kilovault-fetch.service"
	unitPath      = "/etc/systemd/system/" + unitName
)

// Install sets up everything needed for `kilovault fetch` to run
// automatically on every future boot:
//   - the kilovault-consumers group and kilovault system user (primary
//     group kilovault-consumers, so every file `fetch` writes is
//     automatically group-readable by consumers with no explicit chown)
//   - that user's ~/.config/kilovault/ directory, left empty for
//     Terraform (or an operator) to populate with config.json
//   - the systemd unit, enabled but not started (config doesn't exist yet)
//
// Idempotent: safe to run again after it already succeeded, e.g. after a
// binary upgrade. Never touches an existing config.json.
func Install() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("install-service is only supported on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("install-service must be run as root")
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to resolve own binary path: %v", err)
	}

	if err := ensureGroup(consumerGroup); err != nil {
		return err
	}
	if err := ensureUser(serviceUser, consumerGroup, homeDir); err != nil {
		return err
	}
	if err := ensureConfigDir(serviceUser); err != nil {
		return err
	}
	if err := writeUnitFile(execPath); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", unitName); err != nil {
		return err
	}

	fmt.Printf("✓ Installed and enabled %s\n", unitName)
	fmt.Printf("  Next: populate %s/.config/kilovault/config.json (as user %s), then run:\n", homeDir, serviceUser)
	fmt.Printf("    systemctl start %s\n", unitName)
	return nil
}

func ensureGroup(name string) error {
	if err := exec.Command("getent", "group", name).Run(); err == nil {
		return nil
	}
	if out, err := exec.Command("groupadd", "--system", name).CombinedOutput(); err != nil {
		return fmt.Errorf("groupadd %s: %v: %s", name, err, out)
	}
	return nil
}

func ensureUser(name, primaryGroup, home string) error {
	if _, err := user.Lookup(name); err == nil {
		return nil
	} else if _, ok := err.(user.UnknownUserError); !ok {
		return fmt.Errorf("looking up user %s: %v", name, err)
	}

	args := []string{
		"--system",
		"--gid", primaryGroup,
		"--home-dir", home,
		"--create-home",
		"--shell", "/usr/sbin/nologin",
		name,
	}
	if out, err := exec.Command("useradd", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("useradd %s: %v: %s", name, err, out)
	}
	return nil
}

func ensureConfigDir(username string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("looking up user %s: %v", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parsing uid for %s: %v", username, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("parsing gid for %s: %v", username, err)
	}

	configDir := u.HomeDir + "/.config"
	kilovaultDir := configDir + "/kilovault"
	for _, dir := range []string{configDir, kilovaultDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("creating %s: %v", dir, err)
		}
		if err := os.Chown(dir, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %v", dir, err)
		}
	}
	return nil
}

func writeUnitFile(execPath string) error {
	content := renderUnitFile(execPath)
	if err := os.WriteFile(unitPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing %s: %v", unitPath, err)
	}
	return nil
}

// renderUnitFile is kept pure and separate from the file-writing so it's
// unit-testable without touching the filesystem.
func renderUnitFile(execPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Fetch kilovault secrets into local runtime files
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
# Without this, systemd tears down RuntimeDirectory the instant
# ExecStart exits (oneshot has no "running" state to remain in), so
# /run/kilovault would vanish before any consumer got to read it.
RemainAfterExit=yes
User=%s
Group=%s
ExecStart=%s fetch
RuntimeDirectory=kilovault
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=no

[Install]
WantedBy=multi-user.target
`, serviceUser, consumerGroup, execPath)
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %v: %v: %s", args, err, out)
	}
	return nil
}
