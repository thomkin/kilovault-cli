package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// binPath is set by TestMain to a freshly-built kilovault binary.
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "kilovault-cli-test-bin")
	if err != nil {
		panic(err)
	}

	binPath = filepath.Join(dir, "kilovault")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		panic("failed to build kilovault binary: " + err.Error() + "\n" + string(out))
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// runTokenLocal runs `kilovault token local <args...>` with JWT_SECRET set
// and HOME pointed at a fresh temp dir, so --save never touches the real
// user config.
func runTokenLocal(t *testing.T, args ...string) (stdout string, stderr string, err error) {
	t.Helper()

	home := t.TempDir()
	cmdArgs := append([]string{"token", "local"}, args...)
	cmd := exec.Command(binPath, cmdArgs...)
	cmd.Env = append(os.Environ(), "HOME="+home, "JWT_SECRET=test-secret")

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()

	return outBuf.String(), errBuf.String(), err
}

func TestConfig_SecretRoundTrip(t *testing.T) {
	home := t.TempDir()
	runWithHome := func(args ...string) (string, string, error) {
		cmd := exec.Command(binPath, args...)
		cmd.Env = append(os.Environ(), "HOME="+home)
		var outBuf, errBuf strings.Builder
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		err := cmd.Run()
		return outBuf.String(), errBuf.String(), err
	}

	if _, stderr, err := runWithHome("config", "set", "secret", "my-e2e-secret"); err != nil {
		t.Fatalf("config set secret failed: %v\n%s", err, stderr)
	}

	stdout, stderr, err := runWithHome("config", "get", "secret")
	if err != nil {
		t.Fatalf("config get secret failed: %v\n%s", err, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "my-e2e-secret" {
		t.Errorf("config get secret = %q, want %q", got, "my-e2e-secret")
	}

	if _, stderr, err := runWithHome("config", "clear", "secret"); err != nil {
		t.Fatalf("config clear secret failed: %v\n%s", err, stderr)
	}

	stdout2, stderr2, err := runWithHome("config", "get", "secret")
	if err != nil {
		t.Fatalf("config get secret (after clear) failed: %v\n%s", err, stderr2)
	}
	if got := strings.TrimSpace(stdout2); got != "" {
		t.Errorf("config get secret after clear = %q, want empty", got)
	}
}

type jwtPayload struct {
	Sub         string          `json:"sub"`
	Permissions map[string]bool `json:"permissions"`
}

func decodeToken(t *testing.T, token string) jwtPayload {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token, expected 3 parts, got %d: %q", len(parts), token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to base64-decode payload: %v", err)
	}
	var p jwtPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	return p
}

func TestTokenLocal_FlagOrderIndependence(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{
			name: "user first, then permissions/save/expires",
			args: []string{"-u", "admin-user", "-p", `{"admin":true,"history.get":true}`, "-S", "-e", "3600"},
		},
		{
			name: "save/expires/permissions first, user last",
			args: []string{"-S", "-e", "3600", "-p", `{"admin":true,"history.get":true}`, "-u", "admin-user"},
		},
		{
			name: "permissions, save, user, expires interleaved",
			args: []string{"-p", `{"admin":true,"history.get":true}`, "-S", "-u", "admin-user", "-e", "3600"},
		},
		{
			name: "long-form flags",
			args: []string{"--permissions", `{"admin":true,"history.get":true}`, "--save", "--user", "admin-user", "--expires", "3600"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := runTokenLocal(t, tc.args...)
			if err != nil {
				t.Fatalf("unexpected error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
			}

			token := strings.TrimSpace(stdout)
			payload := decodeToken(t, token)

			if payload.Sub != "admin-user" {
				t.Errorf("sub = %q, want %q", payload.Sub, "admin-user")
			}
			if !payload.Permissions["admin"] || !payload.Permissions["history.get"] {
				t.Errorf("permissions = %v, want admin=true, history.get=true", payload.Permissions)
			}
			if !strings.Contains(stderr, "Token saved") {
				t.Errorf("expected save confirmation on stderr, got: %q", stderr)
			}
		})
	}
}

func TestTokenLocal_MissingUserFlag(t *testing.T) {
	_, stderr, err := runTokenLocal(t, "-p", `{"admin":true}`)
	if err == nil {
		t.Fatalf("expected error when -u/--user is omitted, got none")
	}
	if !strings.Contains(stderr, "user id required") {
		t.Errorf("stderr = %q, want it to mention 'user id required'", stderr)
	}
}

func TestTokenLocal_StrayPositionalArgErrors(t *testing.T) {
	_, stderr, err := runTokenLocal(t, "-u", "admin-user", "-p", `{"admin":true}`, "extra-arg")
	if err == nil {
		t.Fatalf("expected error on stray positional argument, got none")
	}
	if !strings.Contains(stderr, "unexpected argument") {
		t.Errorf("stderr = %q, want it to mention 'unexpected argument'", stderr)
	}
}

func TestTokenLocal_OldPositionalStyleNowErrors(t *testing.T) {
	// Pre-fix usage: `token local <userId> -p ...`. The positional userId
	// is gone, so this must fail loudly instead of silently minting a
	// token with an empty/wrong sub and dropped permissions.
	_, stderr, err := runTokenLocal(t, "admin-user", "-p", `{"admin":true}`)
	if err == nil {
		t.Fatalf("expected error for old positional-only usage, got none")
	}
	if stderr == "" {
		t.Errorf("expected a non-empty error message")
	}
}

func TestTokenLocal_NoPermissionsGivenDefaultsEmpty(t *testing.T) {
	stdout, _, err := runTokenLocal(t, "-u", "plain-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := decodeToken(t, strings.TrimSpace(stdout))
	if payload.Sub != "plain-user" {
		t.Errorf("sub = %q, want %q", payload.Sub, "plain-user")
	}
	if len(payload.Permissions) != 0 {
		t.Errorf("permissions = %v, want empty", payload.Permissions)
	}
}

func TestTokenLocal_InvalidPermissionsJSON(t *testing.T) {
	_, stderr, err := runTokenLocal(t, "-u", "admin-user", "-p", "not-json")
	if err == nil {
		t.Fatalf("expected error for invalid permissions JSON, got none")
	}
	if !strings.Contains(stderr, "invalid permissions JSON") {
		t.Errorf("stderr = %q, want it to mention 'invalid permissions JSON'", stderr)
	}
}

// newFakeVaultServer returns an httptest server implementing just enough of
// the /rpc contract (vault.set/vault.get) to exercise the CLI's E2E
// encryption wiring end-to-end, backed by an in-memory key/value store.
func newFakeVaultServer(store map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "vault.set":
			var p struct{ Key, Value string }
			json.Unmarshal(req.Params, &p)
			store[p.Key] = p.Value
			json.NewEncoder(w).Encode(map[string]interface{}{"error": nil, "result": map[string]string{}})
		case "vault.get":
			var p struct{ Key string }
			json.Unmarshal(req.Params, &p)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": nil, "result": map[string]string{"value": store[p.Key]}})
		default:
			http.Error(w, "unknown method: "+req.Method, http.StatusBadRequest)
		}
	}))
}

func TestSetGet_EncryptDecryptRoundTrip(t *testing.T) {
	store := map[string]string{}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "set", "-k", "mykey", "-v", "myvalue", "-s", "the-secret"); err != nil {
		t.Fatalf("set failed: %v\n%s", err, stderr)
	}

	if store["mykey"] == "myvalue" || store["mykey"] == "" {
		t.Fatalf("expected server-stored value to be encrypted ciphertext, got %q", store["mykey"])
	}
	if !strings.HasPrefix(store["mykey"], "enc:v1:") {
		t.Errorf("expected stored value to carry enc:v1: prefix, got %q", store["mykey"])
	}

	stdout, stderr, err := runCLIArgs(t, "-e", server.URL, "get", "-k", "mykey", "-s", "the-secret")
	if err != nil {
		t.Fatalf("get failed: %v\n%s", err, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "myvalue" {
		t.Errorf("get = %q, want %q", got, "myvalue")
	}
}

func TestGet_EncryptedValueWithoutSecretErrors(t *testing.T) {
	store := map[string]string{}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "set", "-k", "mykey", "-v", "myvalue", "-s", "the-secret"); err != nil {
		t.Fatalf("set failed: %v\n%s", err, stderr)
	}

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "get", "-k", "mykey")
	if err == nil {
		t.Fatalf("expected error getting encrypted value without a secret, got none")
	}
	if !strings.Contains(stderr, "encrypted") {
		t.Errorf("stderr = %q, want it to mention the value is encrypted", stderr)
	}
}

func TestGet_EncryptedValueWrongSecretErrors(t *testing.T) {
	store := map[string]string{}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "set", "-k", "mykey", "-v", "myvalue", "-s", "right-secret"); err != nil {
		t.Fatalf("set failed: %v\n%s", err, stderr)
	}

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "get", "-k", "mykey", "-s", "wrong-secret")
	if err == nil {
		t.Fatalf("expected error getting value with wrong secret, got none")
	}
	if !strings.Contains(stderr, "decrypt") {
		t.Errorf("stderr = %q, want it to mention decryption failure", stderr)
	}
}

func TestGet_PlaintextValuePassesThroughUnchanged(t *testing.T) {
	store := map[string]string{"mykey": "plain-legacy-value"}
	server := newFakeVaultServer(store)
	defer server.Close()

	stdout, stderr, err := runCLIArgs(t, "-e", server.URL, "get", "-k", "mykey", "-s", "some-secret")
	if err != nil {
		t.Fatalf("get failed: %v\n%s", err, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "plain-legacy-value" {
		t.Errorf("get = %q, want unchanged plaintext %q", got, "plain-legacy-value")
	}
}

// runCLIArgs runs the kilovault binary with args, using a fresh temp HOME
// so config file reads never leak in an ambient secret/token.
func runCLIArgs(t *testing.T, args ...string) (stdout string, stderr string, err error) {
	t.Helper()
	return runCLIArgsWithEnv(t, nil, args...)
}

// runCLIArgsWithEnv is runCLIArgs plus extra environment variables (e.g.
// KILOVAULT_SECRET), still isolated to a fresh temp HOME.
func runCLIArgsWithEnv(t *testing.T, extraEnv []string, args ...string) (stdout string, stderr string, err error) {
	t.Helper()

	home := t.TempDir()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(append(os.Environ(), "HOME="+home), extraEnv...)

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()

	return outBuf.String(), errBuf.String(), err
}

func TestSetGet_SecretFromEnvVar(t *testing.T) {
	store := map[string]string{}
	server := newFakeVaultServer(store)
	defer server.Close()

	env := []string{"KILOVAULT_SECRET=env-secret"}

	if _, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "set", "-k", "mykey", "-v", "myvalue"); err != nil {
		t.Fatalf("set failed: %v\n%s", err, stderr)
	}
	if !strings.HasPrefix(store["mykey"], "enc:v1:") {
		t.Errorf("expected stored value to carry enc:v1: prefix, got %q", store["mykey"])
	}

	stdout, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "get", "-k", "mykey")
	if err != nil {
		t.Fatalf("get failed: %v\n%s", err, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "myvalue" {
		t.Errorf("get = %q, want %q", got, "myvalue")
	}
}

func TestSet_FlagSecretOverridesEnvVar(t *testing.T) {
	store := map[string]string{}
	server := newFakeVaultServer(store)
	defer server.Close()

	// Set with the flag secret (should win over the env var), then confirm
	// the env-var secret alone cannot decrypt it.
	env := []string{"KILOVAULT_SECRET=env-secret"}
	if _, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "set", "-k", "mykey", "-v", "myvalue", "-s", "flag-secret"); err != nil {
		t.Fatalf("set failed: %v\n%s", err, stderr)
	}

	_, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "get", "-k", "mykey")
	if err == nil {
		t.Fatalf("expected error decrypting with env secret when flag secret was used to encrypt, got none")
	}
	if !strings.Contains(stderr, "decrypt") {
		t.Errorf("stderr = %q, want it to mention decryption failure", stderr)
	}

	stdout, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "get", "-k", "mykey", "-s", "flag-secret")
	if err != nil {
		t.Fatalf("get with correct flag secret failed: %v\n%s", err, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "myvalue" {
		t.Errorf("get = %q, want %q", got, "myvalue")
	}
}

func TestGet_MissingKeyFlagErrors(t *testing.T) {
	_, stderr, err := runCLIArgs(t, "get")
	if err == nil {
		t.Fatalf("expected error when -k/--key is omitted, got none")
	}
	if !strings.Contains(stderr, "key required") {
		t.Errorf("stderr = %q, want it to mention 'key required'", stderr)
	}
}

func TestGet_StrayPositionalArgErrors(t *testing.T) {
	// -k given but with a stray extra positional token trailing (e.g. an
	// old positional-arg invocation habit). Must fail loudly, not silently
	// swallow the stray token (and any flag after it, like -s).
	_, stderr, err := runCLIArgs(t, "get", "-k", "mykey", "extra-arg")
	if err == nil {
		t.Fatalf("expected error for stray positional argument, got none")
	}
	if !strings.Contains(stderr, "unexpected argument") {
		t.Errorf("stderr = %q, want it to mention 'unexpected argument'", stderr)
	}
}

func TestSet_MissingValueFlagErrors(t *testing.T) {
	_, stderr, err := runCLIArgs(t, "set", "-k", "mykey")
	if err == nil {
		t.Fatalf("expected error when -v/--value is omitted, got none")
	}
	if !strings.Contains(stderr, "value required") {
		t.Errorf("stderr = %q, want it to mention 'value required'", stderr)
	}
}

func TestSet_StrayPositionalArgsError(t *testing.T) {
	// Old positional-arg style: `set <key> <value> -s <secret>`. This must
	// fail loudly instead of silently sending the value in plaintext with
	// -s dropped.
	_, stderr, err := runCLIArgs(t, "set", "mykey", "myvalue", "-s", "the-secret")
	if err == nil {
		t.Fatalf("expected error for old positional-only usage, got none")
	}
	if !strings.Contains(stderr, "unexpected argument") && !strings.Contains(stderr, "key required") {
		t.Errorf("stderr = %q, want it to mention the missing/unexpected arguments", stderr)
	}
}

func TestAdminSetGet_EncryptDecryptRoundTrip(t *testing.T) {
	store := map[string]string{}
	server := newFakeAdminServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "admin", "set", "-u", "alice", "-k", "mykey", "-v", "myvalue", "-t", "admintok", "-s", "the-secret"); err != nil {
		t.Fatalf("admin set failed: %v\n%s", err, stderr)
	}

	if !strings.HasPrefix(store["alice/mykey"], "enc:v1:") {
		t.Errorf("expected stored value to carry enc:v1: prefix, got %q", store["alice/mykey"])
	}

	stdout, stderr, err := runCLIArgs(t, "-e", server.URL, "admin", "get", "-u", "alice", "-k", "mykey", "-t", "admintok", "-s", "the-secret")
	if err != nil {
		t.Fatalf("admin get failed: %v\n%s", err, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "myvalue" {
		t.Errorf("admin get = %q, want %q", got, "myvalue")
	}
}

func TestAdminGet_MissingUserFlagErrors(t *testing.T) {
	_, stderr, err := runCLIArgs(t, "admin", "get", "-k", "mykey")
	if err == nil {
		t.Fatalf("expected error when -u/--user is omitted, got none")
	}
	if !strings.Contains(stderr, "user id required") {
		t.Errorf("stderr = %q, want it to mention 'user id required'", stderr)
	}
}

func TestAdminHistory_ShowsActionAndTimestamp(t *testing.T) {
	// Server wire format uses "type"/"createdAt" (its DB column names),
	// not "action"/"timestamp" -- this is the real shape sent by
	// history.get, and the bug this test guards against is the CLI
	// silently zero-valuing Action/Timestamp on a JSON tag mismatch.
	server := newFakeHistoryServer([]map[string]string{
		{"id": "abc-123", "key": "mykey", "type": "get", "createdAt": "2026-01-01T00:00:00Z", "userId": "alice"},
	})
	defer server.Close()

	stdout, stderr, err := runCLIArgs(t, "-e", server.URL, "admin", "history", "-t", "admintok")
	if err != nil {
		t.Fatalf("admin history failed: %v\n%s", err, stderr)
	}

	if !strings.Contains(stdout, "get") {
		t.Errorf("stdout = %q, want it to contain the action %q", stdout, "get")
	}
	if !strings.Contains(stdout, "2026-01-01T00:00:00Z") {
		t.Errorf("stdout = %q, want it to contain the timestamp", stdout)
	}
}

// newFakeHistoryServer fakes history.get, returning the given rows verbatim
// as the "history" result (rows use the server's real wire field names:
// id/key/type/createdAt/userId).
func newFakeHistoryServer(rows []map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "history.get":
			json.NewEncoder(w).Encode(map[string]interface{}{"error": nil, "result": map[string]interface{}{"history": rows}})
		default:
			http.Error(w, "unknown method: "+req.Method, http.StatusBadRequest)
		}
	}))
}

// newFakeAdminServer is like newFakeVaultServer but for vault.admin.get/set,
// keyed by "userId/key".
func newFakeAdminServer(store map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "vault.admin.set":
			var p struct{ UserID, Key, Value string }
			json.Unmarshal(req.Params, &p)
			store[p.UserID+"/"+p.Key] = p.Value
			json.NewEncoder(w).Encode(map[string]interface{}{"error": nil, "result": map[string]string{}})
		case "vault.admin.get":
			var p struct{ UserID, Key string }
			json.Unmarshal(req.Params, &p)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": nil, "result": map[string]string{"value": store[p.UserID+"/"+p.Key]}})
		default:
			http.Error(w, "unknown method: "+req.Method, http.StatusBadRequest)
		}
	}))
}

// attrGet runs `attr` then a plain `get` to read back the raw stored JSON,
// returning it decoded for easy field assertions in tests below.
func attrGetJSON(t *testing.T, serverURL, key string) map[string]interface{} {
	t.Helper()
	stdout, stderr, err := runCLIArgs(t, "-e", serverURL, "get", "-k", key)
	if err != nil {
		t.Fatalf("get failed: %v\n%s", err, stderr)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stored value is not valid JSON: %v\nvalue: %s", err, stdout)
	}
	return doc
}

func TestAttr_SetAddsNewTopLevelAttribute(t *testing.T) {
	store := map[string]string{"mykey": `{"a":1}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "b=2"); err != nil {
		t.Fatalf("attr failed: %v\n%s", err, stderr)
	}

	got := attrGetJSON(t, server.URL, "mykey")
	want := map[string]interface{}{"a": float64(1), "b": float64(2)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored doc = %#v, want %#v", got, want)
	}
}

func TestAttr_SetNestedDotPathWhenIntermediateExists(t *testing.T) {
	store := map[string]string{"mykey": `{"user":{"name":"old","keep":1}}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "user.name=new"); err != nil {
		t.Fatalf("attr failed: %v\n%s", err, stderr)
	}

	got := attrGetJSON(t, server.URL, "mykey")
	want := map[string]interface{}{"user": map[string]interface{}{"name": "new", "keep": float64(1)}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored doc = %#v, want %#v", got, want)
	}
}

func TestAttr_SetMissingIntermediateErrorsAndWritesNothing(t *testing.T) {
	store := map[string]string{"mykey": `{}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "a.b.c=1")
	if err == nil {
		t.Fatalf("expected error setting through a missing intermediate object, got none")
	}
	if !strings.Contains(stderr, "does not exist") {
		t.Errorf("stderr = %q, want it to mention the missing path segment", stderr)
	}
	if store["mykey"] != `{}` {
		t.Errorf("store[mykey] = %q, want unchanged %q", store["mykey"], `{}`)
	}
}

func TestAttr_RemoveTopLevelAndNestedAttribute(t *testing.T) {
	store := map[string]string{"mykey": `{"a":1,"user":{"name":"x","keep":2}}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--remove", "a", "--remove", "user.name"); err != nil {
		t.Fatalf("attr failed: %v\n%s", err, stderr)
	}

	got := attrGetJSON(t, server.URL, "mykey")
	want := map[string]interface{}{"user": map[string]interface{}{"keep": float64(2)}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored doc = %#v, want %#v", got, want)
	}
}

func TestAttr_RemoveMissingPathErrorsAndWritesNothing(t *testing.T) {
	store := map[string]string{"mykey": `{"a":1}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--remove", "missing")
	if err == nil {
		t.Fatalf("expected error removing a path that doesn't exist, got none")
	}
	if !strings.Contains(stderr, "does not exist") {
		t.Errorf("stderr = %q, want it to mention the missing path", stderr)
	}
	if store["mykey"] != `{"a":1}` {
		t.Errorf("store[mykey] = %q, want unchanged %q", store["mykey"], `{"a":1}`)
	}
}

func TestAttr_SetAndRemoveCombinedInOneCall(t *testing.T) {
	store := map[string]string{"mykey": `{"a":1,"b":2}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "c=3", "--remove", "a"); err != nil {
		t.Fatalf("attr failed: %v\n%s", err, stderr)
	}

	got := attrGetJSON(t, server.URL, "mykey")
	want := map[string]interface{}{"b": float64(2), "c": float64(3)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored doc = %#v, want %#v", got, want)
	}
}

func TestAttr_SetOnMissingKeyInitializesEmptyObject(t *testing.T) {
	store := map[string]string{}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "newkey", "--set", "a=1"); err != nil {
		t.Fatalf("attr failed: %v\n%s", err, stderr)
	}

	got := attrGetJSON(t, server.URL, "newkey")
	want := map[string]interface{}{"a": float64(1)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored doc = %#v, want %#v", got, want)
	}
}

func TestAttr_RemoveOnMissingKeyErrorsAndWritesNothing(t *testing.T) {
	store := map[string]string{}
	server := newFakeVaultServer(store)
	defer server.Close()

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "newkey", "--remove", "a")
	if err == nil {
		t.Fatalf("expected error removing from a key that doesn't exist yet, got none")
	}
	if !strings.Contains(stderr, "does not exist") {
		t.Errorf("stderr = %q, want it to mention the missing path", stderr)
	}
	if _, exists := store["newkey"]; exists {
		t.Errorf("expected newkey to remain unwritten, got %q", store["newkey"])
	}
}

func TestAttr_ExistingScalarTopLevelValueErrors(t *testing.T) {
	store := map[string]string{"mykey": `"hello"`}
	server := newFakeVaultServer(store)
	defer server.Close()

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "a=1")
	if err == nil {
		t.Fatalf("expected error setting an attribute path into a scalar JSON value, got none")
	}
	if !strings.Contains(stderr, "expects an object") {
		t.Errorf("stderr = %q, want it to mention the object/scalar mismatch", stderr)
	}
	if store["mykey"] != `"hello"` {
		t.Errorf("store[mykey] = %q, want unchanged %q", store["mykey"], `"hello"`)
	}
}

func TestAttr_ExistingInvalidJSONErrorsAndWritesNothing(t *testing.T) {
	store := map[string]string{"mykey": `not-json{`}
	server := newFakeVaultServer(store)
	defer server.Close()

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "a=1")
	if err == nil {
		t.Fatalf("expected error editing a non-JSON existing value, got none")
	}
	if !strings.Contains(stderr, "not valid JSON") {
		t.Errorf("stderr = %q, want it to mention invalid JSON", stderr)
	}
	if store["mykey"] != `not-json{` {
		t.Errorf("store[mykey] = %q, want unchanged %q", store["mykey"], `not-json{`)
	}
}

func TestAttr_SetValueAutoDetectsType(t *testing.T) {
	store := map[string]string{"mykey": `{}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey",
		"--set", "flagBool=true",
		"--set", "flagNum=42",
		"--set", `flagStr="hi"`,
		"--set", `flagObj={"x":1}`,
		"--set", "flagArr=[1,2]",
		"--set", "flagPlain=helloworld",
	)
	if err != nil {
		t.Fatalf("attr failed: %v\n%s", err, stderr)
	}

	got := attrGetJSON(t, server.URL, "mykey")
	want := map[string]interface{}{
		"flagBool":  true,
		"flagNum":   float64(42),
		"flagStr":   "hi",
		"flagObj":   map[string]interface{}{"x": float64(1)},
		"flagArr":   []interface{}{float64(1), float64(2)},
		"flagPlain": "helloworld",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored doc = %#v, want %#v", got, want)
	}
}

func TestAttr_ArraySetReplaceAndAppend(t *testing.T) {
	store := map[string]string{"mykey": `{"tags":["a","b"]}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "tags.0=z", "--set", "tags.2=c"); err != nil {
		t.Fatalf("attr failed: %v\n%s", err, stderr)
	}

	got := attrGetJSON(t, server.URL, "mykey")
	want := map[string]interface{}{"tags": []interface{}{"z", "b", "c"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored doc = %#v, want %#v", got, want)
	}
}

func TestAttr_ArraySetOutOfBoundsGapErrorsAndWritesNothing(t *testing.T) {
	store := map[string]string{"mykey": `{"tags":["a","b"]}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "tags.5=x")
	if err == nil {
		t.Fatalf("expected error setting an out-of-range array index, got none")
	}
	if !strings.Contains(stderr, "out of range") {
		t.Errorf("stderr = %q, want it to mention the out-of-range index", stderr)
	}
	if store["mykey"] != `{"tags":["a","b"]}` {
		t.Errorf("store[mykey] = %q, want unchanged", store["mykey"])
	}
}

func TestAttr_ArrayRemoveSplicesRatherThanNullingOut(t *testing.T) {
	store := map[string]string{"mykey": `{"tags":["a","b","c"]}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--remove", "tags.1"); err != nil {
		t.Fatalf("attr failed: %v\n%s", err, stderr)
	}

	got := attrGetJSON(t, server.URL, "mykey")
	want := map[string]interface{}{"tags": []interface{}{"a", "c"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored doc = %#v, want %#v (expected splice, not null-out)", got, want)
	}
}

func TestAttr_ArrayRemoveOutOfBoundsErrorsAndWritesNothing(t *testing.T) {
	store := map[string]string{"mykey": `{"tags":["a","b"]}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--remove", "tags.5")
	if err == nil {
		t.Fatalf("expected error removing an out-of-range array index, got none")
	}
	if !strings.Contains(stderr, "out of range") {
		t.Errorf("stderr = %q, want it to mention the out-of-range index", stderr)
	}
	if store["mykey"] != `{"tags":["a","b"]}` {
		t.Errorf("store[mykey] = %q, want unchanged", store["mykey"])
	}
}

func TestAttr_FailingEditInBatchAbortsWholeBatch(t *testing.T) {
	store := map[string]string{"mykey": `{"a":1}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	// The --set would succeed on its own; the --remove targets a path that
	// doesn't exist. Per FR10, the whole batch must abort with nothing
	// written, not just the failing edit.
	_, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "b=2", "--remove", "missing")
	if err == nil {
		t.Fatalf("expected error from the failing --remove, got none")
	}
	if !strings.Contains(stderr, "does not exist") {
		t.Errorf("stderr = %q, want it to mention the missing path", stderr)
	}
	if store["mykey"] != `{"a":1}` {
		t.Errorf("store[mykey] = %q, want unchanged (no partial write of the earlier --set)", store["mykey"])
	}
}

func TestAttr_EncryptionSecretRoundTrip(t *testing.T) {
	store := map[string]string{}
	server := newFakeVaultServer(store)
	defer server.Close()

	if _, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "a=1", "-s", "the-secret"); err != nil {
		t.Fatalf("attr failed: %v\n%s", err, stderr)
	}
	if !strings.HasPrefix(store["mykey"], "enc:v1:") {
		t.Errorf("expected stored value to carry enc:v1: prefix, got %q", store["mykey"])
	}

	stdout, stderr, err := runCLIArgs(t, "-e", server.URL, "get", "-k", "mykey", "-s", "the-secret")
	if err != nil {
		t.Fatalf("get failed: %v\n%s", err, stderr)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &doc); err != nil {
		t.Fatalf("decrypted value is not valid JSON: %v", err)
	}
	if !reflect.DeepEqual(doc, map[string]interface{}{"a": float64(1)}) {
		t.Errorf("decrypted doc = %#v, want {\"a\":1}", doc)
	}
}

func TestAttr_MissingKeyFlagErrors(t *testing.T) {
	_, stderr, err := runCLIArgs(t, "attr", "--set", "a=1")
	if err == nil {
		t.Fatalf("expected error when -k/--key is omitted, got none")
	}
	if !strings.Contains(stderr, "key required") {
		t.Errorf("stderr = %q, want it to mention 'key required'", stderr)
	}
}

func TestAttr_NoSetOrRemoveGivenErrors(t *testing.T) {
	_, stderr, err := runCLIArgs(t, "attr", "-k", "mykey")
	if err == nil {
		t.Fatalf("expected error when neither --set nor --remove is given, got none")
	}
	if !strings.Contains(stderr, "--set or --remove") {
		t.Errorf("stderr = %q, want it to mention --set/--remove", stderr)
	}
}

func TestAttr_StrayPositionalArgErrors(t *testing.T) {
	_, stderr, err := runCLIArgs(t, "attr", "-k", "mykey", "--set", "a=1", "extra-arg")
	if err == nil {
		t.Fatalf("expected error for stray positional argument, got none")
	}
	if !strings.Contains(stderr, "unexpected argument") {
		t.Errorf("stderr = %q, want it to mention 'unexpected argument'", stderr)
	}
}

func TestAttr_InvalidSetSyntaxErrors(t *testing.T) {
	store := map[string]string{"mykey": `{}`}
	server := newFakeVaultServer(store)
	defer server.Close()

	_, stderr, err := runCLIArgs(t, "-e", server.URL, "attr", "-k", "mykey", "--set", "no-equals-sign")
	if err == nil {
		t.Fatalf("expected error for --set without '=', got none")
	}
	if !strings.Contains(stderr, "path=value") {
		t.Errorf("stderr = %q, want it to mention the expected path=value syntax", stderr)
	}
}
