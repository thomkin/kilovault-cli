package client

import "testing"

func TestParseSyncKeys_Valid(t *testing.T) {
	entries, err := ParseSyncKeys(`[{"key":"db_password","as":"DB_PASSWORD"},{"key":"api_key"}]`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Key != "db_password" || entries[0].As != "DB_PASSWORD" {
		t.Errorf("entries[0] = %+v, want Key=db_password As=DB_PASSWORD", entries[0])
	}
	if entries[1].Key != "api_key" || entries[1].As != "" {
		t.Errorf("entries[1] = %+v, want Key=api_key As=\"\"", entries[1])
	}
}

func TestParseSyncKeys_InvalidJSONErrors(t *testing.T) {
	_, err := ParseSyncKeys("not-json")
	if err == nil {
		t.Fatalf("expected error for invalid JSON, got none")
	}
}

func TestParseSyncKeys_EmptyArrayErrors(t *testing.T) {
	_, err := ParseSyncKeys(`[]`)
	if err == nil {
		t.Fatalf("expected error for empty array, got none")
	}
}

func TestParseSyncKeys_MissingKeyErrors(t *testing.T) {
	_, err := ParseSyncKeys(`[{"as":"FOO"}]`)
	if err == nil {
		t.Fatalf("expected error when key is missing, got none")
	}
}

func TestParseSyncKeys_DuplicateOutputNameViaAsErrors(t *testing.T) {
	_, err := ParseSyncKeys(`[{"key":"a","as":"SAME"},{"key":"b","as":"SAME"}]`)
	if err == nil {
		t.Fatalf("expected error for duplicate output name, got none")
	}
}

func TestParseSyncKeys_DuplicateOutputNameKeyVsAsErrors(t *testing.T) {
	// second entry's default output name (its Key, "a") collides with the
	// first entry's explicit override.
	_, err := ParseSyncKeys(`[{"key":"x","as":"a"},{"key":"a"}]`)
	if err == nil {
		t.Fatalf("expected error for output name collision between as and key, got none")
	}
}

func TestSyncKeyEntry_OutputName(t *testing.T) {
	cases := []struct {
		entry SyncKeyEntry
		want  string
	}{
		{SyncKeyEntry{Key: "db_password", As: "DB_PASSWORD"}, "DB_PASSWORD"},
		{SyncKeyEntry{Key: "api_key"}, "api_key"},
	}
	for _, tc := range cases {
		if got := tc.entry.OutputName(); got != tc.want {
			t.Errorf("OutputName(%+v) = %q, want %q", tc.entry, got, tc.want)
		}
	}
}
