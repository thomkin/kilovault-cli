package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomkin/kilovault-cli/pkg/client"
)

// newFakeBatchServer is like newFakeVaultServer/newFakeAdminServer combined,
// plus vault.admin.delete, since `batch run` can exercise all four RPCs
// (vault.get/set, vault.admin.set/delete) in one invocation.
func newFakeBatchServer(store map[string]string) *httptest.Server {
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
		case "vault.admin.set":
			var p struct{ UserID, Key, Value string }
			json.Unmarshal(req.Params, &p)
			store[p.UserID+"/"+p.Key] = p.Value
			json.NewEncoder(w).Encode(map[string]interface{}{"error": nil, "result": map[string]string{}})
		case "vault.admin.get":
			var p struct{ UserID, Key string }
			json.Unmarshal(req.Params, &p)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": nil, "result": map[string]string{"value": store[p.UserID+"/"+p.Key]}})
		case "vault.admin.list":
			var p struct {
				UserID *string `json:"userId"`
			}
			json.Unmarshal(req.Params, &p)
			keys := []client.VaultKey{}
			for k := range store {
				userID, key, ok := strings.Cut(k, "/")
				if !ok {
					continue // not an admin-namespaced entry (a plain vault.set key)
				}
				if p.UserID != nil && userID != *p.UserID {
					continue
				}
				keys = append(keys, client.VaultKey{Key: key, UserID: userID})
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"error": nil, "result": map[string]interface{}{"keys": keys}})
		case "vault.admin.delete":
			var p struct{ UserID, Key string }
			json.Unmarshal(req.Params, &p)
			k := p.UserID + "/" + p.Key
			_, existed := store[k]
			delete(store, k)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": nil, "result": map[string]bool{"deleted": existed}})
		default:
			http.Error(w, "unknown method: "+req.Method, http.StatusBadRequest)
		}
	}))
}

func writeBatchPlainFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "batch.plain.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write plaintext batch file: %v", err)
	}
	return path
}

func encryptBatchFile(t *testing.T, plainContent string) string {
	t.Helper()
	inPath := writeBatchPlainFile(t, plainContent)
	outPath := filepath.Join(t.TempDir(), "batch.enc")

	if _, stderr, err := runCLIArgsWithEnv(t, []string{"KILOVAULT_BATCH_SECRET=batch-secret"}, "batch", "encrypt", "-i", inPath, "-o", outPath); err != nil {
		t.Fatalf("batch encrypt failed: %v\n%s", err, stderr)
	}
	return outPath
}

func TestBatch_EncryptRunRoundTrip_SetOps(t *testing.T) {
	store := map[string]string{}
	server := newFakeBatchServer(store)
	defer server.Close()

	batchFile := encryptBatchFile(t, `[
		{"op":"set","key":"db_password","value":"hunter2"},
		{"op":"set","key":"api_key","value":"abc123","user":"svc-user-1"}
	]`)

	env := []string{"KILOVAULT_BATCH_SECRET=batch-secret"}
	stdout, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "batch", "run", "-f", batchFile)
	if err != nil {
		t.Fatalf("batch run failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Batch complete: 2 op(s)") {
		t.Errorf("stdout = %q, want it to mention batch completion", stdout)
	}
	if store["db_password"] != "hunter2" {
		t.Errorf("store[db_password] = %q, want %q", store["db_password"], "hunter2")
	}
	if store["svc-user-1/api_key"] != "abc123" {
		t.Errorf("store[svc-user-1/api_key] = %q, want %q", store["svc-user-1/api_key"], "abc123")
	}
}

func TestBatch_RunWithValueSecret_EncryptsEachValue(t *testing.T) {
	store := map[string]string{}
	server := newFakeBatchServer(store)
	defer server.Close()

	batchFile := encryptBatchFile(t, `[{"op":"set","key":"mykey","value":"myvalue"}]`)

	env := []string{"KILOVAULT_BATCH_SECRET=batch-secret"}
	_, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "batch", "run", "-f", batchFile, "-s", "value-secret")
	if err != nil {
		t.Fatalf("batch run failed: %v\n%s", err, stderr)
	}
	if !strings.HasPrefix(store["mykey"], "enc:v1:") {
		t.Errorf("expected stored value to carry enc:v1: prefix, got %q", store["mykey"])
	}

	stdout, stderr, err := runCLIArgs(t, "-e", server.URL, "get", "-k", "mykey", "-s", "value-secret")
	if err != nil {
		t.Fatalf("get failed: %v\n%s", err, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "myvalue" {
		t.Errorf("get = %q, want %q", got, "myvalue")
	}
}

func TestBatch_AttrOp_SetAndRemove(t *testing.T) {
	store := map[string]string{"mykey": `{"a":1,"old":true,"nested":{"name":"y"}}`}
	server := newFakeBatchServer(store)
	defer server.Close()

	batchFile := encryptBatchFile(t, `[
		{"op":"attr","key":"mykey","set":[{"path":"b","value":2},{"path":"nested.name","value":"x"}],"remove":["old"]}
	]`)

	env := []string{"KILOVAULT_BATCH_SECRET=batch-secret"}
	_, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "batch", "run", "-f", batchFile)
	if err != nil {
		t.Fatalf("batch run failed: %v\n%s", err, stderr)
	}

	var got map[string]interface{}
	if err := json.Unmarshal([]byte(store["mykey"]), &got); err != nil {
		t.Fatalf("stored value is not valid JSON: %v", err)
	}
	nested, _ := got["nested"].(map[string]interface{})
	if got["a"] != float64(1) || got["b"] != float64(2) || got["old"] != nil || nested["name"] != "x" {
		t.Errorf("stored doc = %#v, want a=1 b=2 old=<removed> nested.name=x", got)
	}
}

func TestBatch_DeleteOp(t *testing.T) {
	store := map[string]string{"alice/mykey": "somevalue"}
	server := newFakeBatchServer(store)
	defer server.Close()

	batchFile := encryptBatchFile(t, `[{"op":"delete","key":"mykey","user":"alice"}]`)

	env := []string{"KILOVAULT_BATCH_SECRET=batch-secret"}
	_, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "batch", "run", "-f", batchFile)
	if err != nil {
		t.Fatalf("batch run failed: %v\n%s", err, stderr)
	}
	if _, exists := store["alice/mykey"]; exists {
		t.Errorf("expected alice/mykey to be deleted, still present: %q", store["alice/mykey"])
	}
}

func TestBatch_MixedOpsInOneFile(t *testing.T) {
	store := map[string]string{"bob/old": "gone-soon"}
	server := newFakeBatchServer(store)
	defer server.Close()

	batchFile := encryptBatchFile(t, `[
		{"op":"set","key":"k1","value":"v1"},
		{"op":"attr","key":"k2","set":[{"path":"active","value":true}]},
		{"op":"delete","key":"old","user":"bob"}
	]`)

	env := []string{"KILOVAULT_BATCH_SECRET=batch-secret"}
	stdout, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "batch", "run", "-f", batchFile)
	if err != nil {
		t.Fatalf("batch run failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Batch complete: 3 op(s)") {
		t.Errorf("stdout = %q, want it to mention 3 ops", stdout)
	}
	if store["k1"] != "v1" {
		t.Errorf("store[k1] = %q, want %q", store["k1"], "v1")
	}
	if _, exists := store["bob/old"]; exists {
		t.Errorf("expected bob/old to be deleted")
	}
}

func TestBatch_StopsOnFirstFailure(t *testing.T) {
	store := map[string]string{"mykey": `{}`}
	server := newFakeBatchServer(store)
	defer server.Close()

	// Second op removes a path that doesn't exist -> fails. Third op
	// must never run.
	batchFile := encryptBatchFile(t, `[
		{"op":"set","key":"k1","value":"v1"},
		{"op":"attr","key":"mykey","remove":["missing"]},
		{"op":"set","key":"k3","value":"v3"}
	]`)

	env := []string{"KILOVAULT_BATCH_SECRET=batch-secret"}
	_, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "batch", "run", "-f", batchFile)
	if err == nil {
		t.Fatalf("expected error from the failing attr op, got none")
	}
	if !strings.Contains(stderr, "batch stopped after 1/3") {
		t.Errorf("stderr = %q, want it to mention batch stopped after 1/3", stderr)
	}
	if store["k1"] != "v1" {
		t.Errorf("expected the first (successful) op to still be applied, store[k1] = %q", store["k1"])
	}
	if _, exists := store["k3"]; exists {
		t.Errorf("expected the third op to never run, but store[k3] = %q", store["k3"])
	}
}

func TestBatch_WrongBatchSecretErrors(t *testing.T) {
	batchFile := encryptBatchFile(t, `[{"op":"set","key":"k1","value":"v1"}]`)

	_, stderr, err := runCLIArgsWithEnv(t, []string{"KILOVAULT_BATCH_SECRET=wrong-secret"}, "batch", "run", "-f", batchFile)
	if err == nil {
		t.Fatalf("expected error decrypting with the wrong batch secret, got none")
	}
	if !strings.Contains(stderr, "failed to decrypt batch file") {
		t.Errorf("stderr = %q, want it to mention decryption failure", stderr)
	}
}

func TestBatch_MissingBatchSecretErrors(t *testing.T) {
	batchFile := encryptBatchFile(t, `[{"op":"set","key":"k1","value":"v1"}]`)

	_, stderr, err := runCLIArgs(t, "batch", "run", "-f", batchFile)
	if err == nil {
		t.Fatalf("expected error when no batch secret is given, got none")
	}
	if !strings.Contains(stderr, "batch file secret required") {
		t.Errorf("stderr = %q, want it to mention batch file secret required", stderr)
	}
}

func TestBatch_UnencryptedFileRejected(t *testing.T) {
	path := writeBatchPlainFile(t, `[{"op":"set","key":"k1","value":"v1"}]`)

	_, stderr, err := runCLIArgsWithEnv(t, []string{"KILOVAULT_BATCH_SECRET=whatever"}, "batch", "run", "-f", path)
	if err == nil {
		t.Fatalf("expected error running an unencrypted file, got none")
	}
	if !strings.Contains(stderr, "is not encrypted") {
		t.Errorf("stderr = %q, want it to mention the file is not encrypted", stderr)
	}
}

func TestBatch_EncryptRejectsInvalidBatchContent(t *testing.T) {
	inPath := writeBatchPlainFile(t, `[{"op":"nonsense","key":"k1"}]`)
	outPath := filepath.Join(t.TempDir(), "batch.enc")

	_, stderr, err := runCLIArgsWithEnv(t, []string{"KILOVAULT_BATCH_SECRET=batch-secret"}, "batch", "encrypt", "-i", inPath, "-o", outPath)
	if err == nil {
		t.Fatalf("expected error encrypting an invalid batch file, got none")
	}
	if !strings.Contains(stderr, "not a valid batch file") {
		t.Errorf("stderr = %q, want it to mention invalid batch file", stderr)
	}
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Errorf("expected no output file to be written on validation failure")
	}
}

func TestBatch_DecryptPrintsPlaintextToStdout(t *testing.T) {
	content := `[{"op":"set","key":"k1","value":"v1"}]`
	batchFile := encryptBatchFile(t, content)

	stdout, _, err := runCLIArgsWithEnv(t, []string{"KILOVAULT_BATCH_SECRET=batch-secret"}, "batch", "decrypt", "-f", batchFile)
	if err != nil {
		t.Fatalf("batch decrypt failed: %v", err)
	}
	if strings.TrimSpace(stdout) != content {
		t.Errorf("stdout = %q, want %q", strings.TrimSpace(stdout), content)
	}
}

func TestBatch_DecryptWithOutWritesFileMode0600(t *testing.T) {
	content := `[{"op":"set","key":"k1","value":"v1"}]`
	batchFile := encryptBatchFile(t, content)
	outPath := filepath.Join(t.TempDir(), "decrypted.json")

	_, stderr, err := runCLIArgsWithEnv(t, []string{"KILOVAULT_BATCH_SECRET=batch-secret"}, "batch", "decrypt", "-f", batchFile, "-o", outPath)
	if err != nil {
		t.Fatalf("batch decrypt failed: %v\n%s", err, stderr)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read decrypted output: %v", err)
	}
	if string(data) != content {
		t.Errorf("decrypted file content = %q, want %q", data, content)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("failed to stat output file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("output file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestBatch_RunStrayPositionalArgErrors(t *testing.T) {
	batchFile := encryptBatchFile(t, `[{"op":"set","key":"k1","value":"v1"}]`)

	_, stderr, err := runCLIArgsWithEnv(t, []string{"KILOVAULT_BATCH_SECRET=batch-secret"}, "batch", "run", "-f", batchFile, "extra-arg")
	if err == nil {
		t.Fatalf("expected error for stray positional argument, got none")
	}
	if !strings.Contains(stderr, "unexpected argument") {
		t.Errorf("stderr = %q, want it to mention unexpected argument", stderr)
	}
}

func TestBatch_ExportThenRunRestoresExactly(t *testing.T) {
	// alice's key is already client-side ciphertext (as if `admin set -s`
	// had been used); bob's is plain. Export must capture both verbatim,
	// and restoring into a *different* empty store must reproduce them
	// byte-for-byte -- proving Raw ops don't get re-encrypted on restore.
	source := map[string]string{
		"alice/db_password": "enc:v1:not-real-ciphertext-but-opaque-to-us==",
		"bob/api_key":       "plain-value",
	}
	sourceServer := newFakeBatchServer(source)
	defer sourceServer.Close()

	backupPath := filepath.Join(t.TempDir(), "backup.enc")
	env := []string{"KILOVAULT_BATCH_SECRET=backup-secret"}

	stdout, stderr, err := runCLIArgsWithEnv(t, env, "-e", sourceServer.URL, "batch", "export", "-o", backupPath, "-t", "admintok")
	if err != nil {
		t.Fatalf("batch export failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Exported 2 key(s)") {
		t.Errorf("stdout = %q, want it to mention 2 keys exported", stdout)
	}

	dest := map[string]string{}
	destServer := newFakeBatchServer(dest)
	defer destServer.Close()

	if _, stderr, err := runCLIArgsWithEnv(t, env, "-e", destServer.URL, "batch", "run", "-f", backupPath, "-t", "admintok"); err != nil {
		t.Fatalf("batch run (restore) failed: %v\n%s", err, stderr)
	}

	if dest["alice/db_password"] != source["alice/db_password"] {
		t.Errorf("restored alice/db_password = %q, want exact match %q", dest["alice/db_password"], source["alice/db_password"])
	}
	if dest["bob/api_key"] != source["bob/api_key"] {
		t.Errorf("restored bob/api_key = %q, want exact match %q", dest["bob/api_key"], source["bob/api_key"])
	}
}

func TestBatch_ExportRestoreWithSecretDoesNotDoubleEncrypt(t *testing.T) {
	// Even if -s/--secret is passed on restore (as a habit from other
	// commands), a Raw op must ignore it -- otherwise an already-
	// encrypted exported value would get wrapped in a second layer of
	// encryption and become permanently undecryptable with either secret.
	source := map[string]string{"alice/secret_key": "enc:v1:AAAA"}
	sourceServer := newFakeBatchServer(source)
	defer sourceServer.Close()

	backupPath := filepath.Join(t.TempDir(), "backup.enc")
	env := []string{"KILOVAULT_BATCH_SECRET=backup-secret"}
	if _, stderr, err := runCLIArgsWithEnv(t, env, "-e", sourceServer.URL, "batch", "export", "-o", backupPath, "-t", "admintok"); err != nil {
		t.Fatalf("batch export failed: %v\n%s", err, stderr)
	}

	dest := map[string]string{}
	destServer := newFakeBatchServer(dest)
	defer destServer.Close()

	if _, stderr, err := runCLIArgsWithEnv(t, env, "-e", destServer.URL, "batch", "run", "-f", backupPath, "-t", "admintok", "-s", "some-value-secret"); err != nil {
		t.Fatalf("batch run (restore) failed: %v\n%s", err, stderr)
	}

	if dest["alice/secret_key"] != "enc:v1:AAAA" {
		t.Errorf("restored alice/secret_key = %q, want unchanged %q (not re-encrypted)", dest["alice/secret_key"], "enc:v1:AAAA")
	}
}

func TestBatch_ExportScopedToOneUser(t *testing.T) {
	store := map[string]string{
		"alice/k1": "v1",
		"bob/k2":   "v2",
	}
	server := newFakeBatchServer(store)
	defer server.Close()

	backupPath := filepath.Join(t.TempDir(), "backup.enc")
	env := []string{"KILOVAULT_BATCH_SECRET=backup-secret"}
	stdout, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "batch", "export", "-o", backupPath, "-t", "admintok", "-u", "alice")
	if err != nil {
		t.Fatalf("batch export failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Exported 1 key(s)") {
		t.Errorf("stdout = %q, want it to mention 1 key exported", stdout)
	}

	plaintext, _, err := runCLIArgsWithEnv(t, env, "batch", "decrypt", "-f", backupPath)
	if err != nil {
		t.Fatalf("batch decrypt failed: %v", err)
	}
	if strings.Contains(plaintext, "bob") {
		t.Errorf("scoped export leaked bob's key into the backup: %s", plaintext)
	}
	if !strings.Contains(plaintext, `"key":"k1"`) {
		t.Errorf("scoped export missing alice's key: %s", plaintext)
	}
}

func TestBatch_ExportNoKeysErrors(t *testing.T) {
	store := map[string]string{}
	server := newFakeBatchServer(store)
	defer server.Close()

	backupPath := filepath.Join(t.TempDir(), "backup.enc")
	env := []string{"KILOVAULT_BATCH_SECRET=backup-secret"}
	_, stderr, err := runCLIArgsWithEnv(t, env, "-e", server.URL, "batch", "export", "-o", backupPath, "-t", "admintok")
	if err == nil {
		t.Fatalf("expected error exporting an empty vault, got none")
	}
	if !strings.Contains(stderr, "no keys found") {
		t.Errorf("stderr = %q, want it to mention no keys found", stderr)
	}
}

func TestBatch_ExportMissingOutFlagErrors(t *testing.T) {
	_, stderr, err := runCLIArgs(t, "batch", "export", "-t", "admintok")
	if err == nil {
		t.Fatalf("expected error when -o/--out is omitted, got none")
	}
	if !strings.Contains(stderr, "output file required") {
		t.Errorf("stderr = %q, want it to mention output file required", stderr)
	}
}
