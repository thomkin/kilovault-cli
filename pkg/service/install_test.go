package service

import (
	"strings"
	"testing"
)

// renderUnitFile is the only piece of install.go that doesn't require root
// or a real systemd — the rest (ensureGroup, ensureUser, ensureConfigDir,
// writeUnitFile, systemctl) shells out to system-mutating commands and is
// exercised manually/in Step 5's coverage notes instead.
func TestRenderUnitFile_ContainsExpectedDirectives(t *testing.T) {
	unit := renderUnitFile("/usr/local/bin/kilovault")

	wantSubstrings := []string{
		"Type=oneshot",
		"User=kilovault",
		"Group=kilovault-consumers",
		"ExecStart=/usr/local/bin/kilovault fetch",
		"RuntimeDirectory=kilovault",
		"RuntimeDirectoryMode=0750",
		"RuntimeDirectoryPreserve=no",
		"WantedBy=multi-user.target",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(unit, want) {
			t.Errorf("rendered unit missing %q:\n%s", want, unit)
		}
	}
}

func TestRenderUnitFile_UsesGivenExecPath(t *testing.T) {
	unit := renderUnitFile("/opt/custom/path/kilovault")
	if !strings.Contains(unit, "ExecStart=/opt/custom/path/kilovault fetch") {
		t.Errorf("rendered unit did not use given exec path:\n%s", unit)
	}
}
