package client

import (
	"encoding/json"
	"fmt"
)

// BatchSetEdit is one path/value edit within an "attr" batch op, applied
// in list order (same semantics as repeated --set flags on the `attr`
// command, but Value is already a decoded JSON value rather than a
// string that still needs type auto-detection).
type BatchSetEdit struct {
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// BatchOp is one operation in a batch file. Op selects which fields are
// used/required:
//
//   - "set": Key and Value are required. User is optional — if given,
//     the write goes through vault.admin.set for that user (needs an
//     admin token) instead of the caller's own vault.set. Raw is
//     optional: if true, Value is written to the server exactly as
//     given, skipping the run's -s/--secret client-side encryption
//     pass — used by `batch export` so a value that's already
//     ciphertext (or already deliberately plaintext) round-trips
//     byte-for-byte on `batch run` instead of being encrypted again.
//   - "attr": Key is required, plus at least one of Set/Remove. Edits a
//     JSON-object vault value in place, same semantics as the `attr`
//     command (Remove applied before Set). No User field — like the
//     `attr` command, this always operates on the caller's own key.
//   - "delete": Key and User are required. There is no non-admin delete
//     command, so User can't be omitted here either.
type BatchOp struct {
	Op     string         `json:"op"`
	Key    string         `json:"key"`
	Value  *string        `json:"value,omitempty"`
	User   string         `json:"user,omitempty"`
	Raw    bool           `json:"raw,omitempty"`
	Set    []BatchSetEdit `json:"set,omitempty"`
	Remove []string       `json:"remove,omitempty"`
}

// ParseBatch decodes and validates a batch file's decrypted JSON
// content: a JSON array of BatchOp. It rejects the whole batch on the
// first invalid op so execution never starts partway into a malformed
// file.
func ParseBatch(data []byte) ([]BatchOp, error) {
	var ops []BatchOp
	if err := json.Unmarshal(data, &ops); err != nil {
		return nil, fmt.Errorf("invalid batch JSON: %v", err)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("batch file contains no operations")
	}

	for i, op := range ops {
		if err := op.validate(); err != nil {
			return nil, fmt.Errorf("op[%d]: %v", i, err)
		}
	}
	return ops, nil
}

func (op BatchOp) validate() error {
	if op.Key == "" {
		return fmt.Errorf("key is required")
	}

	switch op.Op {
	case "":
		return fmt.Errorf(`"op" is required`)

	case "set":
		if op.Value == nil {
			return fmt.Errorf(`op "set" requires "value"`)
		}
		if len(op.Set) > 0 || len(op.Remove) > 0 {
			return fmt.Errorf(`op "set" does not accept "set"/"remove" (did you mean op "attr"?)`)
		}

	case "attr":
		if op.Value != nil {
			return fmt.Errorf(`op "attr" does not accept "value"`)
		}
		if op.User != "" {
			return fmt.Errorf(`op "attr" does not accept "user" (attr always operates on the caller's own key)`)
		}
		if op.Raw {
			return fmt.Errorf(`op "attr" does not accept "raw"`)
		}
		if len(op.Set) == 0 && len(op.Remove) == 0 {
			return fmt.Errorf(`op "attr" requires at least one "set" or "remove" entry`)
		}
		for j, e := range op.Set {
			if e.Path == "" {
				return fmt.Errorf("set[%d]: empty path", j)
			}
		}
		for j, p := range op.Remove {
			if p == "" {
				return fmt.Errorf("remove[%d]: empty path", j)
			}
		}

	case "delete":
		if op.User == "" {
			return fmt.Errorf(`op "delete" requires "user" (there is no non-admin delete command)`)
		}
		if op.Value != nil || op.Raw || len(op.Set) > 0 || len(op.Remove) > 0 {
			return fmt.Errorf(`op "delete" does not accept "value"/"raw"/"set"/"remove"`)
		}

	default:
		return fmt.Errorf(`unknown op %q (expected "set", "attr", or "delete")`, op.Op)
	}

	return nil
}
