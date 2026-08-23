package export

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRenderEnv_QuotingAndEscaping(t *testing.T) {
	kvs := []KeyValue{
		{Name: "SIMPLE", Value: "plainvalue"},
		{Name: "WITH_QUOTE", Value: `has "quotes"`},
		{Name: "WITH_BACKSLASH", Value: `back\slash`},
		{Name: "WITH_NEWLINE", Value: "line1\nline2"},
		{Name: "WITH_CR", Value: "line1\r\nline2"},
		{Name: "EMPTY", Value: ""},
	}
	want := "SIMPLE=\"plainvalue\"\n" +
		`WITH_QUOTE="has \"quotes\""` + "\n" +
		`WITH_BACKSLASH="back\\slash"` + "\n" +
		`WITH_NEWLINE="line1\nline2"` + "\n" +
		`WITH_CR="line1\r\nline2"` + "\n" +
		`EMPTY=""` + "\n"

	got := string(RenderEnv(kvs))
	if got != want {
		t.Errorf("RenderEnv =\n%q\nwant\n%q", got, want)
	}
}

func TestRenderEnv_PreservesInputOrder(t *testing.T) {
	kvs := []KeyValue{
		{Name: "Z_LAST", Value: "1"},
		{Name: "A_FIRST", Value: "2"},
	}
	got := string(RenderEnv(kvs))
	wantOrder := "Z_LAST=\"1\"\nA_FIRST=\"2\"\n"
	if got != wantOrder {
		t.Errorf("RenderEnv did not preserve input order: got %q, want %q", got, wantOrder)
	}
}

func TestRenderYAML_RoundTrip(t *testing.T) {
	kvs := []KeyValue{
		{Name: "DB_PASSWORD", Value: `p@ss "word"` + "\nwith-newline"},
		{Name: "API_KEY", Value: "simple123"},
	}

	data, err := RenderYAML(kvs)
	if err != nil {
		t.Fatalf("RenderYAML returned error: %v", err)
	}

	var back map[string]string
	if err := yaml.Unmarshal(data, &back); err != nil {
		t.Fatalf("failed to parse RenderYAML output back as YAML: %v\noutput:\n%s", err, data)
	}

	for _, kv := range kvs {
		if back[kv.Name] != kv.Value {
			t.Errorf("round-tripped[%q] = %q, want %q", kv.Name, back[kv.Name], kv.Value)
		}
	}
}

func TestRenderAnsibleFacts_ValidJSON(t *testing.T) {
	kvs := []KeyValue{
		{Name: "DB_PASSWORD", Value: `p@ss "word"`},
		{Name: "API_KEY", Value: "simple123"},
	}

	data, err := RenderAnsibleFacts(kvs)
	if err != nil {
		t.Fatalf("RenderAnsibleFacts returned error: %v", err)
	}

	var back map[string]string
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("failed to parse RenderAnsibleFacts output as JSON: %v\noutput:\n%s", err, data)
	}

	for _, kv := range kvs {
		if back[kv.Name] != kv.Value {
			t.Errorf("round-tripped[%q] = %q, want %q", kv.Name, back[kv.Name], kv.Value)
		}
	}
}

func TestValidateEnvName(t *testing.T) {
	cases := map[string]bool{
		"GOOD_NAME":  true,
		"_LEADING":   true,
		"lower_case": true,
		"N4me_With9": true,
		"bad-name!":  false,
		"9leading":   false,
		"has space":  false,
		"":           false,
	}
	for name, wantValid := range cases {
		err := ValidateEnvName(name)
		if (err == nil) != wantValid {
			t.Errorf("ValidateEnvName(%q) error = %v, want valid=%v", name, err, wantValid)
		}
	}
}
