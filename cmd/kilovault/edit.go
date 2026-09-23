package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/thomkin/kilovault-cli/pkg/profiles"
	"github.com/thomkin/kilovault-cli/pkg/securestore"
	"github.com/urfave/cli/v2"
)

func runProfilesEdit(c *cli.Context) error {
	user := c.String("user")
	if err := profiles.ValidateUser(user); err != nil {
		return err
	}
	// Check the plaintext can stay in RAM before unlocking anything.
	runtimeDir, err := ramEditDir()
	if err != nil {
		return err
	}

	e, err := openProfilesEnv(c, true)
	if err != nil {
		return err
	}
	defer e.close()

	prof, err := e.loadForEdit(user)
	if err != nil {
		return err
	}

	edited, err := editInRAM(runtimeDir, user, profiles.RenderDoc(prof.Values), e.p.tty)
	if err != nil || edited == nil {
		return err
	}

	prof.Values = profiles.MergeEdit(prof.Values, edited)
	changes := prof.Changes()
	if err := e.save(prof); err != nil {
		return fmt.Errorf("failed to save profile: %v", err)
	}
	if len(changes) == 0 {
		fmt.Println("No changes.")
		return nil
	}

	printChanges(user, changes, c.Bool("show-values"))
	if !c.Bool("yes") && !e.p.confirm("Push these changes now?") {
		fmt.Printf("Saved locally (encrypted). Push later with `kilovault profiles push -u %s`.\n", user)
		return nil
	}
	return e.push([]string{user}, false, true, false)
}

// loadForEdit returns the profile to edit: freshly pulled if it has no
// unpushed changes (so edits start from the server's current values),
// otherwise the local working copy with those changes.
func (e *profilesEnv) loadForEdit(user string) (*profiles.Profile, error) {
	if profiles.Exists(e.dir, user) {
		prof, err := e.load(user)
		if err != nil {
			return nil, err
		}
		if n := len(prof.Changes()); n > 0 {
			fmt.Fprintf(os.Stderr, "%s has %d unpushed change(s); editing them (not pulling)\n", user, n)
			return prof, nil
		}
	}

	byUser, err := e.remoteKeys(user)
	if err != nil {
		return nil, err
	}
	if keys := byUser[user]; len(keys) > 0 {
		ok, err := e.pullUser(user, keys, true)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("could not pull %s", user)
		}
	} else if !profiles.Exists(e.dir, user) {
		return nil, fmt.Errorf("no profile %q locally or on %s — create it with `kilovault profiles new -u %s`", user, e.endpoint, user)
	}
	return e.load(user)
}

// ramEditDir returns $XDG_RUNTIME_DIR if it is RAM-backed. Decrypted
// profiles are never written anywhere else.
func ramEditDir() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return "", errors.New("XDG_RUNTIME_DIR is not set, so there's no RAM-only place for the decrypted file — refusing to edit (log in through a normal session, or set it to a tmpfs directory you own)")
	}
	ram, err := securestore.IsRAMBacked(dir)
	if err != nil {
		return "", fmt.Errorf("can't check %s: %v", dir, err)
	}
	if !ram {
		return "", fmt.Errorf("%s is not RAM-backed (tmpfs) — refusing to write decrypted secrets to it", dir)
	}
	return dir, nil
}

// editInRAM writes content to a private temp file under runtimeDir, runs
// the editor on it until it parses (re-opening on errors when
// interactive), and returns the parsed values, or nil if the file wasn't
// changed. The temp file is zeroed and removed on every exit path,
// including SIGTERM/SIGHUP.
func editInRAM(runtimeDir, user string, content []byte, interactive bool) (map[string]string, error) {
	tmpDir, err := os.MkdirTemp(runtimeDir, "kilovault-edit-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(tmpDir, user+".json")

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			if info, err := os.Stat(path); err == nil {
				if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
					f.Write(make([]byte, info.Size()))
					f.Close()
				}
			}
			os.RemoveAll(tmpDir)
		})
	}
	defer cleanup()

	// Ctrl-C while the editor runs belongs to the editor; anywhere else it
	// aborts. SIGTERM/SIGHUP always abort. Either way, clean up first.
	var editorRunning atomic.Bool
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer func() {
		signal.Stop(sigs)
		close(sigs)
	}()
	go func() {
		for sig := range sigs {
			if sig == os.Interrupt && editorRunning.Load() {
				continue
			}
			cleanup()
			fmt.Fprintln(os.Stderr, "\nAborted — nothing was saved.")
			os.Exit(1)
		}
	}()

	if err := os.WriteFile(path, content, 0600); err != nil {
		return nil, err
	}

	for {
		editorRunning.Store(true)
		err := runEditor(path)
		editorRunning.Store(false)
		if err != nil {
			return nil, err
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(data, content) {
			securestore.Wipe(data)
			fmt.Println("No changes.")
			return nil, nil
		}
		values, perr := profiles.ParseDoc(data)
		securestore.Wipe(data)
		if perr == nil {
			return values, nil
		}

		fmt.Fprintf(os.Stderr, "✗ %s.json %v\n", user, perr)
		if !interactive {
			return nil, perr
		}
		if !newPrompter().confirm("Edit again? (no = abort, discarding your edits)") {
			return nil, errors.New("aborted — nothing was saved")
		}
	}
}

// editorEnv overrides the editor for `profiles edit` only.
const editorEnv = "KILOVAULT_EDITOR"

// hardenedEditors are tried in order when KILOVAULT_EDITOR isn't set:
// the vim family is the only one whose swap/backup/undo/history files we
// can switch off, so it's preferred over $VISUAL/$EDITOR for editing
// decrypted secrets.
var hardenedEditors = []string{"nvim", "vim", "vi"}

// resolveEditor picks the editor command: $KILOVAULT_EDITOR, else the
// first installed of nvim/vim/vi, else $VISUAL / $EDITOR.
func resolveEditor() (string, error) {
	if editor := strings.TrimSpace(os.Getenv(editorEnv)); editor != "" {
		return editor, nil
	}
	for _, name := range hardenedEditors {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	for _, env := range []string{"VISUAL", "EDITOR"} {
		if editor := strings.TrimSpace(os.Getenv(env)); editor != "" {
			return editor, nil
		}
	}
	return "", fmt.Errorf("no editor found: install nvim, vim or vi, or set %s", editorEnv)
}

// runEditor opens path in the editor from resolveEditor. For vim-family
// editors it disables swap, backup, undo and viminfo files, which could
// otherwise copy the plaintext to disk.
func runEditor(path string) error {
	editor, err := resolveEditor()
	if err != nil {
		return err
	}
	fields := strings.Fields(editor)
	args := fields[1:]
	switch filepath.Base(fields[0]) {
	case "vi", "vim", "nvim", "gvim", "vimx":
		args = append(args, "-n", "-i", "NONE", "--cmd", "set nobackup nowritebackup noundofile")
	}
	args = append(args, path)

	cmd := exec.Command(fields[0], args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor %q failed: %v — nothing was saved", editor, err)
	}
	return nil
}
