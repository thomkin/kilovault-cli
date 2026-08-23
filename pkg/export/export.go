// Package export renders a set of fetched vault key/value pairs into the
// file formats kilovault-cli's `fetch` command writes to disk. All
// functions here are pure (no I/O, no root/network) so they're directly
// unit-testable.
package export

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// KeyValue is one fetched vault key, under the local name it should be
// exposed as (see client.SyncKeyEntry.OutputName).
type KeyValue struct {
	Name  string
	Value string
}

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateEnvName reports whether name is usable as a shell/env variable
// name. A sync-keys entry whose OutputName() fails this is almost
// certainly a config mistake — better surfaced loudly than silently
// producing a .env file the other two output formats disagree with.
func ValidateEnvName(name string) error {
	if !envNamePattern.MatchString(name) {
		return fmt.Errorf("%q is not a valid environment variable name", name)
	}
	return nil
}

// RenderEnv produces .env-file content: NAME="value" per line, double-quoted
// with backslash/quote escaping and literal newlines/carriage-returns encoded
// as \n/\r — the convention common dotenv parsers (godotenv, python-dotenv,
// Docker --env-file) expect, so the output round-trips through them.
func RenderEnv(kvs []KeyValue) []byte {
	var buf strings.Builder
	for _, kv := range kvs {
		buf.WriteString(kv.Name)
		buf.WriteByte('=')
		buf.WriteString(quoteEnvValue(kv.Value))
		buf.WriteByte('\n')
	}
	return []byte(buf.String())
}

func quoteEnvValue(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func toMap(kvs []KeyValue) map[string]string {
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		m[kv.Name] = kv.Value
	}
	return m
}

// RenderYAML produces a flat `name: value` YAML mapping.
func RenderYAML(kvs []KeyValue) ([]byte, error) {
	return yaml.Marshal(toMap(kvs))
}

// RenderAnsibleFacts produces the JSON body of an Ansible custom facts
// (.fact) file: a flat {"name": "value"} object, which Ansible surfaces as
// ansible_local.kilovault.<name> once fact_path points at its directory.
func RenderAnsibleFacts(kvs []KeyValue) ([]byte, error) {
	return json.MarshalIndent(toMap(kvs), "", "  ")
}
