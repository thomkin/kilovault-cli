package profiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"
)

// The editable form of a profile is one JSON object: vault key → value.
//
//   - A JSON string is stored in the vault exactly as written.
//   - Any other JSON value (object, array, number, bool, null) is stored
//     as its compact JSON text — e.g. a whole config file for a service.
//
// Rendering goes the other way: a vault value that is a JSON object or
// array is shown as nested JSON, anything else as a JSON string. So
// values round-trip, and editing a nested object doesn't change how
// untouched values are stored.

// ValidateKey reports whether key is usable as a vault key in a profile.
func ValidateKey(key string) error {
	if key == "" {
		return errors.New("empty key")
	}
	for _, r := range key {
		if unicode.IsControl(r) {
			return fmt.Errorf("key %q contains control characters", key)
		}
	}
	return nil
}

// RenderDoc renders values as the editable JSON document, keys sorted.
func RenderDoc(values map[string]string) []byte {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b bytes.Buffer
	if len(keys) == 0 {
		b.WriteString("{\n}\n")
		return b.Bytes()
	}
	b.WriteString("{\n")
	for i, k := range keys {
		b.WriteString("  ")
		b.Write(marshalString(k))
		b.WriteString(": ")
		b.Write(renderValue(values[k]))
		if i < len(keys)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}\n")
	return b.Bytes()
}

func renderValue(v string) []byte {
	trimmed := strings.TrimSpace(v)
	if trimmed == v && v != "" && (v[0] == '{' || v[0] == '[') && json.Valid([]byte(v)) {
		var out bytes.Buffer
		if json.Indent(&out, []byte(v), "  ", "  ") == nil {
			return out.Bytes()
		}
	}
	return marshalString(v)
}

// marshalString encodes s as a JSON string without HTML escaping, so
// values like "a<b&c" stay readable in the editor.
func marshalString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// ParseDoc parses an edited document back into vault values. It rejects
// anything but a single top-level object, duplicate keys (which plain
// JSON decoding would silently collapse), and empty values. Errors
// carry a line number.
func ParseDoc(data []byte) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	lineErr := func(err error) error { return withLine(data, dec.InputOffset(), err) }

	tok, err := dec.Token()
	if err != nil {
		return nil, syntaxErr(data, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, lineErr(errors.New("the document must be a JSON object: { \"KEY\": \"value\", ... }"))
	}

	values := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, syntaxErr(data, err)
		}
		key := tok.(string) // object keys are always strings
		if err := ValidateKey(key); err != nil {
			return nil, lineErr(err)
		}
		if _, dup := values[key]; dup {
			return nil, lineErr(fmt.Errorf("duplicate key %q", key))
		}

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, syntaxErr(data, err)
		}
		value, err := docValue(raw)
		if err != nil {
			return nil, lineErr(fmt.Errorf("%q: %v", key, err))
		}
		values[key] = value
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, syntaxErr(data, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, lineErr(errors.New("unexpected content after the closing }"))
	}
	return values, nil
}

// docValue converts one document value to the string stored in the vault.
func docValue(raw json.RawMessage) (string, error) {
	var s string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", err
		}
		if s == "" {
			return "", errors.New("empty value (remove the key to delete it)")
		}
		return s, nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return "", err
	}
	return compact.String(), nil
}

func syntaxErr(data []byte, err error) error {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return withLine(data, se.Offset, err)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return withLine(data, int64(len(data)), errors.New("unexpected end of document (missing } or \"?)"))
	}
	return err
}

func withLine(data []byte, offset int64, err error) error {
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	line := 1 + bytes.Count(data[:offset], []byte("\n"))
	return fmt.Errorf("line %d: %v", line, err)
}

// MergeEdit turns the values parsed from an edited document into the new
// working copy. A value whose edited form equals the canonical form of
// its previous value keeps the previous string exactly, so rendering and
// re-parsing (e.g. "[1, 2]" → "[1,2]") never shows up as a change.
func MergeEdit(previous, edited map[string]string) map[string]string {
	merged := make(map[string]string, len(edited))
	for key, v := range edited {
		if old, ok := previous[key]; ok && canonical(old) == v {
			v = old
		}
		merged[key] = v
	}
	return merged
}

// canonical is what v becomes after RenderDoc + ParseDoc.
func canonical(v string) string {
	rendered := renderValue(v)
	if rendered[0] == '"' {
		return v
	}
	var compact bytes.Buffer
	if json.Compact(&compact, rendered) != nil {
		return v
	}
	return compact.String()
}
