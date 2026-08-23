package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/thomkin/kilovault-cli/pkg/client"
	"github.com/thomkin/kilovault-cli/pkg/export"
	"github.com/urfave/cli/v2"
)

const defaultRuntimeDir = "/run/kilovault"

// runFetch is the `kilovault fetch` action: reads the sync-keys configured
// in config.json, fetches each from the server, and writes the results as
// YAML, .env, and an Ansible custom-facts file into the systemd-managed
// runtime directory. Meant to be invoked by the installed systemd unit, not
// run interactively.
func runFetch(c *cli.Context) error {
	cfg, err := client.LoadConfigFile()
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}
	if len(cfg.SyncKeys) == 0 {
		return fmt.Errorf("no sync-keys configured — run `kilovault config set sync-keys '[...]'`")
	}

	runtimeDir := os.Getenv("RUNTIME_DIRECTORY")
	if runtimeDir == "" {
		runtimeDir = defaultRuntimeDir // fallback for manual/non-systemd invocation
	}

	cl := client.NewWithToken(getEndpoint(c), "")
	secret := client.ResolveSecret("")

	kvs := make([]export.KeyValue, 0, len(cfg.SyncKeys))
	for _, entry := range cfg.SyncKeys {
		if err := export.ValidateEnvName(entry.OutputName()); err != nil {
			return fmt.Errorf("sync-keys entry %q: %v", entry.Key, err)
		}

		result, err := cl.VaultGet(entry.Key)
		if err != nil {
			return fmt.Errorf("fetch %s: request failed: %v", entry.Key, err)
		}
		if result.Value == "" {
			return fmt.Errorf("fetch %s: key not set on server", entry.Key)
		}

		value, err := decryptIfNeeded(result.Value, secret)
		if err != nil {
			return fmt.Errorf("fetch %s: %v", entry.Key, err)
		}

		kvs = append(kvs, export.KeyValue{Name: entry.OutputName(), Value: value})
	}

	yamlData, err := export.RenderYAML(kvs)
	if err != nil {
		return fmt.Errorf("rendering YAML: %v", err)
	}
	factsData, err := export.RenderAnsibleFacts(kvs)
	if err != nil {
		return fmt.Errorf("rendering Ansible facts: %v", err)
	}

	if err := writeAtomic(runtimeDir, "env.yaml", yamlData); err != nil {
		return err
	}
	if err := writeAtomic(runtimeDir, ".env", export.RenderEnv(kvs)); err != nil {
		return err
	}
	if err := writeAtomic(runtimeDir, "kilovault.fact", factsData); err != nil {
		return err
	}

	fmt.Printf("✓ Fetched %d key(s) into %s\n", len(kvs), runtimeDir)
	return nil
}

// writeAtomic writes data to a temp file in dir and renames it into place —
// same-directory rename is atomic, so a concurrent reader never observes a
// partially-written file.
func writeAtomic(dir, name string, data []byte) error {
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return fmt.Errorf("write %s: %v", name, err)
	}
	if err := os.Chmod(tmp, 0640); err != nil { // guard against umask
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("rename into place %s: %v", name, err)
	}
	return nil
}
