package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomkin/kilovault-cli/pkg/client"
	"github.com/thomkin/kilovault-cli/pkg/securestore"
)

// profilesSetup starts a fake vault holding store, initializes a
// credentials store against it, and stores alice's E2E secret.
func profilesSetup(t *testing.T, store map[string]string) (home string, env []string) {
	t.Helper()
	server := newFakeBatchServer(store)
	t.Cleanup(server.Close)
	home = initStore(t, server.URL)
	env = masterEnv(testMasterPW)
	if _, stderr, err := runCLIHome(t, home, env, "alice-secret\n", "credentials", "set-secret", "-u", "alice", "--skip-verify"); err != nil {
		t.Fatalf("set-secret: %v\n%s", err, stderr)
	}
	return home, env
}

func encFor(t *testing.T, secret, v string) string {
	t.Helper()
	out, err := client.Encrypt(secret, v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func decFor(t *testing.T, secret, v string) string {
	t.Helper()
	out, err := client.Decrypt(secret, v)
	if err != nil {
		t.Fatalf("decrypt %q: %v", v, err)
	}
	return out
}

func profilesDir(home string) string {
	return filepath.Join(home, ".config", "kilovault", "profiles")
}

// ramRuntimeDir returns a fresh tmpfs-backed XDG_RUNTIME_DIR for edit
// tests, or skips when no tmpfs is available.
func ramRuntimeDir(t *testing.T) string {
	t.Helper()
	if ok, err := securestore.IsRAMBacked("/dev/shm"); err != nil || !ok {
		t.Skip("/dev/shm is not tmpfs here")
	}
	dir, err := os.MkdirTemp("/dev/shm", "kv-test-runtime-")
	if err != nil {
		t.Skip("can't create a dir in /dev/shm")
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// fakeEditor returns env vars that make `profiles edit` use a script
// which saves the document it was given to seenPath and replaces it
// with newDoc.
func fakeEditor(t *testing.T, newDoc string) (env []string, seenPath string) {
	t.Helper()
	dir := t.TempDir()
	seenPath = filepath.Join(dir, "seen.json")
	docPath := filepath.Join(dir, "new.json")
	if err := os.WriteFile(docPath, []byte(newDoc), 0600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "editor.sh")
	body := "#!/bin/sh\nfor f; do :; done\ncp \"$f\" '" + seenPath + "'\ncat '" + docPath + "' > \"$f\"\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return []string{editorEnv + "=" + script}, seenPath
}

func TestProfiles_PullStoresEncryptedFiles(t *testing.T) {
	store := map[string]string{
		"alice/DB_PASSWORD": encFor(t, "alice-secret", "hunter2"),
		"alice/GRAFANA":     `{"url":"https://g"}`,
		"bob/API_KEY":       "plain-bob-key",
	}
	home, env := profilesSetup(t, store)

	if _, stderr, err := runCLIHome(t, home, env, "", "profiles", "pull"); err != nil {
		t.Fatalf("pull: %v\n%s", err, stderr)
	}
	for _, user := range []string{"alice", "bob"} {
		raw, err := os.ReadFile(filepath.Join(profilesDir(home), user+".json.enc"))
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"hunter2", "plain-bob-key", "DB_PASSWORD", "grafana"} {
			if strings.Contains(string(raw), leak) {
				t.Errorf("%s profile file leaks %q", user, leak)
			}
		}
	}

	stdout, _, err := runCLIHome(t, home, env, "", "profiles", "list")
	if err != nil || !strings.Contains(stdout, "alice") || !strings.Contains(stdout, "bob") {
		t.Errorf("list = %q, %v", stdout, err)
	}
	stdout, _, _ = runCLIHome(t, home, env, "", "profiles", "diff")
	if !strings.Contains(stdout, "No unpushed changes") {
		t.Errorf("diff right after pull:\n%s", stdout)
	}

	stdout, _, err = runCLIHome(t, home, env, "", "profiles", "list", "--keys", "-u", "alice")
	if err != nil || !strings.Contains(stdout, "alice:\n  DB_PASSWORD\n  GRAFANA\n") || strings.Contains(stdout, "bob") {
		t.Errorf("list --keys -u alice = %q, %v", stdout, err)
	}
	for _, leak := range []string{"hunter2", "https://g"} {
		if strings.Contains(stdout, leak) {
			t.Errorf("list --keys leaks value %q", leak)
		}
	}
	if _, _, err := runCLIHome(t, home, env, "", "profiles", "list", "-u", "carol"); err == nil {
		t.Error("list -u for a missing profile succeeded")
	}
}

func TestProfiles_PullSkipsProfileWithoutSecret(t *testing.T) {
	store := map[string]string{
		"carol/K":     encFor(t, "carol-secret", "v"),
		"bob/API_KEY": "plain",
	}
	home, env := profilesSetup(t, store)

	_, stderr, err := runCLIHome(t, home, env, "", "profiles", "pull")
	if err == nil || !strings.Contains(stderr, "carol: skipped") || !strings.Contains(stderr, "set-secret -u carol") {
		t.Fatalf("err=%v stderr=%s", err, stderr)
	}
	if _, err := os.Stat(filepath.Join(profilesDir(home), "bob.json.enc")); err != nil {
		t.Error("bob should still be pulled")
	}
	if _, err := os.Stat(filepath.Join(profilesDir(home), "carol.json.enc")); err == nil {
		t.Error("carol should be skipped")
	}
}

func TestProfiles_EditAndPush(t *testing.T) {
	store := map[string]string{
		"alice/DB_PASSWORD": encFor(t, "alice-secret", "hunter2"),
		"alice/GRAFANA":     `{"url": "https://g"}`, // plaintext, non-compact
		"alice/OLD":         encFor(t, "alice-secret", "bye"),
	}
	home, env := profilesSetup(t, store)
	runtime := ramRuntimeDir(t)

	edEnv, seen := fakeEditor(t, `{
  "DB_PASSWORD": "new-password",
  "GRAFANA": {
    "url": "https://g"
  },
  "NEW_CONFIG": {"port": 8080, "tls": true}
}`)
	env = append(append(env, edEnv...), "XDG_RUNTIME_DIR="+runtime)

	stdout, stderr, err := runCLIHome(t, home, env, "", "profiles", "edit", "-u", "alice", "-y")
	if err != nil {
		t.Fatalf("edit: %v\n%s%s", err, stdout, stderr)
	}

	// The editor saw the pulled values as a JSON document.
	shown, _ := os.ReadFile(seen)
	for _, want := range []string{`"DB_PASSWORD": "hunter2"`, `"GRAFANA": {`, `"OLD": "bye"`} {
		if !strings.Contains(string(shown), want) {
			t.Errorf("editor document missing %q:\n%s", want, shown)
		}
	}

	// Only real edits were pushed; modes kept, new keys encrypted.
	if got := decFor(t, "alice-secret", store["alice/DB_PASSWORD"]); got != "new-password" {
		t.Errorf("DB_PASSWORD = %q", got)
	}
	if store["alice/GRAFANA"] != `{"url": "https://g"}` {
		t.Errorf("untouched GRAFANA was rewritten: %q", store["alice/GRAFANA"])
	}
	if got := decFor(t, "alice-secret", store["alice/NEW_CONFIG"]); got != `{"port":8080,"tls":true}` {
		t.Errorf("NEW_CONFIG = %q (want encrypted compact JSON)", got)
	}
	if _, ok := store["alice/OLD"]; ok {
		t.Error("OLD should be deleted")
	}
	for _, want := range []string{"~ DB_PASSWORD", "+ NEW_CONFIG", "- OLD", "Pushed 3 change(s)"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "new-password") {
		t.Error("values printed without --show-values")
	}

	if entries, _ := os.ReadDir(runtime); len(entries) != 0 {
		t.Errorf("decrypted temp files left in the runtime dir: %v", entries)
	}
	if stdout, _, _ := runCLIHome(t, home, env, "", "profiles", "diff"); !strings.Contains(stdout, "No unpushed changes") {
		t.Errorf("diff after push:\n%s", stdout)
	}
}

func TestProfiles_EditWithoutPushKeepsChangesEncrypted(t *testing.T) {
	store := map[string]string{"alice/K": encFor(t, "alice-secret", "v1")}
	home, env := profilesSetup(t, store)
	edEnv, _ := fakeEditor(t, `{"K": "v2"}`)
	env = append(append(env, edEnv...), "XDG_RUNTIME_DIR="+ramRuntimeDir(t))

	// No -y and no answer on stdin → not pushed, kept locally.
	stdout, stderr, err := runCLIHome(t, home, env, "", "profiles", "edit", "-u", "alice")
	if err != nil || !strings.Contains(stdout, "Saved locally") {
		t.Fatalf("edit: %v\n%s%s", err, stdout, stderr)
	}
	if decFor(t, "alice-secret", store["alice/K"]) != "v1" {
		t.Fatal("pushed without confirmation")
	}

	stdout, _, _ = runCLIHome(t, home, env, "", "profiles", "diff", "--show-values")
	if !strings.Contains(stdout, `~ K: "v1" → "v2"`) {
		t.Errorf("diff --show-values:\n%s", stdout)
	}

	// pull must not clobber the unpushed edit.
	if _, _, err := runCLIHome(t, home, env, "", "profiles", "pull"); err == nil {
		t.Error("pull overwrote unpushed changes")
	}

	if _, stderr, err := runCLIHome(t, home, env, "", "profiles", "push", "-y"); err != nil {
		t.Fatalf("push: %v\n%s", err, stderr)
	}
	if decFor(t, "alice-secret", store["alice/K"]) != "v2" {
		t.Error("push didn't apply the saved edit")
	}
}

func TestProfiles_EditRejectsInvalidDocument(t *testing.T) {
	store := map[string]string{"alice/K": encFor(t, "alice-secret", "v1")}
	home, env := profilesSetup(t, store)
	runtime := ramRuntimeDir(t)
	edEnv, _ := fakeEditor(t, "{\n  \"K\": \"v2\",\n  \"K\": \"v3\"\n}")
	env = append(append(env, edEnv...), "XDG_RUNTIME_DIR="+runtime)

	_, stderr, err := runCLIHome(t, home, env, "", "profiles", "edit", "-u", "alice", "-y")
	if err == nil || !strings.Contains(stderr, `line 3: duplicate key "K"`) {
		t.Fatalf("err=%v stderr=%s", err, stderr)
	}
	if decFor(t, "alice-secret", store["alice/K"]) != "v1" {
		t.Error("invalid edit was pushed")
	}
	if entries, _ := os.ReadDir(runtime); len(entries) != 0 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestProfiles_EditRefusesDiskBackedRuntimeDir(t *testing.T) {
	store := map[string]string{"alice/K": "v"}
	home, env := profilesSetup(t, store)
	diskDir, _ := os.Getwd()
	if ok, _ := securestore.IsRAMBacked(diskDir); ok {
		t.Skip("working dir is on tmpfs here")
	}
	edEnv, _ := fakeEditor(t, `{"K": "x"}`)
	env = append(append(env, edEnv...), "XDG_RUNTIME_DIR="+diskDir)

	_, stderr, err := runCLIHome(t, home, env, "", "profiles", "edit", "-u", "alice", "-y")
	if err == nil || !strings.Contains(stderr, "not RAM-backed") {
		t.Errorf("err=%v stderr=%s", err, stderr)
	}
	env = append(env, "XDG_RUNTIME_DIR=")
	if _, stderr, err := runCLIHome(t, home, env, "", "profiles", "edit", "-u", "alice", "-y"); err == nil || !strings.Contains(stderr, "XDG_RUNTIME_DIR is not set") {
		t.Errorf("unset: err=%v stderr=%s", err, stderr)
	}
}

func TestProfiles_PushDetectsRemoteConflict(t *testing.T) {
	store := map[string]string{"alice/K": encFor(t, "alice-secret", "v1")}
	home, env := profilesSetup(t, store)
	edEnv, _ := fakeEditor(t, `{"K": "mine"}`)
	env = append(append(env, edEnv...), "XDG_RUNTIME_DIR="+ramRuntimeDir(t))

	if _, stderr, err := runCLIHome(t, home, env, "", "profiles", "edit", "-u", "alice"); err != nil {
		t.Fatalf("edit: %v\n%s", err, stderr)
	}
	store["alice/K"] = encFor(t, "alice-secret", "theirs")

	_, stderr, err := runCLIHome(t, home, env, "", "profiles", "push", "-y")
	if err == nil || !strings.Contains(stderr, "changed on the server since the last pull") {
		t.Fatalf("err=%v stderr=%s", err, stderr)
	}
	if decFor(t, "alice-secret", store["alice/K"]) != "theirs" {
		t.Fatal("conflicting push wrote anyway")
	}
	if _, stderr, err := runCLIHome(t, home, env, "", "profiles", "push", "-y", "--force"); err != nil {
		t.Fatalf("push --force: %v\n%s", err, stderr)
	}
	if decFor(t, "alice-secret", store["alice/K"]) != "mine" {
		t.Error("--force didn't overwrite")
	}
}

func TestProfiles_NewProfileGetsOwnSecret(t *testing.T) {
	store := map[string]string{}
	home, env := profilesSetup(t, store)
	edEnv, _ := fakeEditor(t, `{"TOKEN": "xyz"}`)
	env = append(append(env, edEnv...), "XDG_RUNTIME_DIR="+ramRuntimeDir(t))

	if _, stderr, err := runCLIHome(t, home, env, "", "profiles", "new", "-u", "carol"); err != nil {
		t.Fatalf("new: %v\n%s", err, stderr)
	}
	if _, _, err := runCLIHome(t, home, env, "", "profiles", "new", "-u", "carol"); err == nil {
		t.Error("second new overwrote the profile")
	}
	if _, stderr, err := runCLIHome(t, home, env, "", "profiles", "edit", "-u", "carol", "-y"); err != nil {
		t.Fatalf("edit: %v\n%s", err, stderr)
	}

	secret, _, _ := runCLIHome(t, home, env, "", "credentials", "show-secret", "-u", "carol")
	secret = strings.TrimSpace(secret)
	if secret == "" || secret == "alice-secret" {
		t.Fatalf("carol's secret = %q", secret)
	}
	if got := decFor(t, secret, store["carol/TOKEN"]); got != "xyz" {
		t.Errorf("carol/TOKEN = %q", got)
	}
	if _, err := client.Decrypt("alice-secret", store["carol/TOKEN"]); err == nil {
		t.Error("carol's value decrypts with alice's secret")
	}
}

func TestProfiles_RenamedFileIsRejected(t *testing.T) {
	store := map[string]string{"alice/K": "v", "bob/K": "w"}
	home, env := profilesSetup(t, store)
	if _, stderr, err := runCLIHome(t, home, env, "", "profiles", "pull"); err != nil {
		t.Fatalf("pull: %v\n%s", err, stderr)
	}
	dir := profilesDir(home)
	os.Rename(filepath.Join(dir, "alice.json.enc"), filepath.Join(dir, "bob.json.enc"))

	_, stderr, err := runCLIHome(t, home, env, "", "profiles", "diff", "-u", "bob")
	if err == nil || !strings.Contains(stderr, `sealed as profile`) {
		t.Errorf("err=%v stderr=%s", err, stderr)
	}
}

func TestProfiles_RequireInit(t *testing.T) {
	_, stderr, err := runCLIHome(t, t.TempDir(), masterEnv(testMasterPW), "", "profiles", "pull")
	if err == nil || !strings.Contains(stderr, "kilovault init") {
		t.Errorf("err=%v stderr=%s", err, stderr)
	}
}

func TestResolveEditor_Order(t *testing.T) {
	bin := t.TempDir()
	fake := func(name string) string {
		p := filepath.Join(bin, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Setenv("PATH", bin)
	t.Setenv("EDITOR", "nano")
	t.Setenv("VISUAL", "")
	t.Setenv(editorEnv, "")

	// No vi-family editor installed: fall back to $EDITOR.
	if got, err := resolveEditor(); err != nil || got != "nano" {
		t.Errorf("fallback = %q, %v; want nano", got, err)
	}

	// vi beats $EDITOR; nvim beats vi.
	vi := fake("vi")
	if got, _ := resolveEditor(); got != vi {
		t.Errorf("with vi installed = %q, want %q", got, vi)
	}
	nvim := fake("nvim")
	if got, _ := resolveEditor(); got != nvim {
		t.Errorf("with nvim installed = %q, want %q", got, nvim)
	}

	// KILOVAULT_EDITOR beats everything.
	t.Setenv(editorEnv, "code --wait")
	if got, _ := resolveEditor(); got != "code --wait" {
		t.Errorf("override = %q", got)
	}

	// Nothing at all: a clear error.
	t.Setenv(editorEnv, "")
	t.Setenv("EDITOR", "")
	t.Setenv("PATH", t.TempDir())
	if _, err := resolveEditor(); err == nil || !strings.Contains(err.Error(), editorEnv) {
		t.Errorf("no editor: err = %v", err)
	}
}
