package client

import (
	"encoding/json"
	"fmt"
)

// SyncKeyEntry names one vault key that `kilovault fetch` should pull down,
// and optionally the local name to expose it as (env var / YAML key /
// Ansible fact name). If As is empty, Key is used for both.
type SyncKeyEntry struct {
	Key string `json:"key"`
	As  string `json:"as,omitempty"`
}

// OutputName returns As if set, otherwise Key.
func (e SyncKeyEntry) OutputName() string {
	if e.As != "" {
		return e.As
	}
	return e.Key
}

// ParseSyncKeys validates and parses the JSON array value accepted by
// `kilovault config set sync-keys`, e.g.:
//
//	[{"key":"db_password","as":"DB_PASSWORD"},{"key":"api_key"}]
//
// Rejects malformed input immediately rather than deferring failure to
// boot time, when `kilovault fetch` runs unattended.
func ParseSyncKeys(raw string) ([]SyncKeyEntry, error) {
	var entries []SyncKeyEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("invalid sync-keys JSON: %v", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("sync-keys must contain at least one entry")
	}

	seen := make(map[string]bool, len(entries))
	for i, e := range entries {
		if e.Key == "" {
			return nil, fmt.Errorf("sync-keys[%d]: key is required", i)
		}
		name := e.OutputName()
		if seen[name] {
			return nil, fmt.Errorf("sync-keys[%d]: duplicate output name %q", i, name)
		}
		seen[name] = true
	}
	return entries, nil
}
