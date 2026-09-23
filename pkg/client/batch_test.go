package client

import (
	"strings"
	"testing"
)

func TestParseBatch_ValidSetOp(t *testing.T) {
	ops, err := ParseBatch([]byte(`[{"op":"set","key":"k","value":"v"}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ops) != 1 || ops[0].Op != "set" || ops[0].Key != "k" || ops[0].Value == nil || *ops[0].Value != "v" {
		t.Errorf("unexpected parsed ops: %#v", ops)
	}
}

func TestParseBatch_ValidSetOpWithUser(t *testing.T) {
	ops, err := ParseBatch([]byte(`[{"op":"set","key":"k","value":"v","user":"alice"}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ops[0].User != "alice" {
		t.Errorf("User = %q, want %q", ops[0].User, "alice")
	}
}

func TestParseBatch_ValidAttrOp(t *testing.T) {
	ops, err := ParseBatch([]byte(`[{"op":"attr","key":"k","set":[{"path":"a","value":true}],"remove":["b"]}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ops[0].Set) != 1 || ops[0].Set[0].Path != "a" || ops[0].Set[0].Value != true {
		t.Errorf("unexpected Set: %#v", ops[0].Set)
	}
	if len(ops[0].Remove) != 1 || ops[0].Remove[0] != "b" {
		t.Errorf("unexpected Remove: %#v", ops[0].Remove)
	}
}

func TestParseBatch_ValidDeleteOp(t *testing.T) {
	ops, err := ParseBatch([]byte(`[{"op":"delete","key":"k","user":"alice"}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ops[0].Op != "delete" || ops[0].User != "alice" {
		t.Errorf("unexpected parsed op: %#v", ops[0])
	}
}

func TestParseBatch_MultipleOpsInOrder(t *testing.T) {
	ops, err := ParseBatch([]byte(`[
		{"op":"set","key":"a","value":"1"},
		{"op":"set","key":"b","value":"2"},
		{"op":"attr","key":"c","set":[{"path":"x","value":1}]}
	]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("len(ops) = %d, want 3", len(ops))
	}
}

func TestParseBatch_InvalidJSONErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`not json`))
	if err == nil || !strings.Contains(err.Error(), "invalid batch JSON") {
		t.Errorf("err = %v, want it to mention invalid batch JSON", err)
	}
}

func TestParseBatch_EmptyArrayErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[]`))
	if err == nil || !strings.Contains(err.Error(), "no operations") {
		t.Errorf("err = %v, want it to mention no operations", err)
	}
}

func TestParseBatch_MissingKeyErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"set","value":"v"}]`))
	if err == nil || !strings.Contains(err.Error(), "key is required") {
		t.Errorf("err = %v, want it to mention key is required", err)
	}
}

func TestParseBatch_MissingOpErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"key":"k","value":"v"}]`))
	if err == nil || !strings.Contains(err.Error(), `"op" is required`) {
		t.Errorf("err = %v, want it to mention op is required", err)
	}
}

func TestParseBatch_UnknownOpErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"wipe","key":"k"}]`))
	if err == nil || !strings.Contains(err.Error(), "unknown op") {
		t.Errorf("err = %v, want it to mention unknown op", err)
	}
}

func TestParseBatch_SetWithoutValueErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"set","key":"k"}]`))
	if err == nil || !strings.Contains(err.Error(), `requires "value"`) {
		t.Errorf("err = %v, want it to mention value is required", err)
	}
}

func TestParseBatch_SetWithSetFieldErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"set","key":"k","value":"v","set":[{"path":"a","value":1}]}]`))
	if err == nil || !strings.Contains(err.Error(), `does not accept "set"`) {
		t.Errorf("err = %v, want it to mention set/remove not accepted", err)
	}
}

func TestParseBatch_AttrWithValueErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"attr","key":"k","value":"v","set":[{"path":"a","value":1}]}]`))
	if err == nil || !strings.Contains(err.Error(), `does not accept "value"`) {
		t.Errorf("err = %v, want it to mention value not accepted", err)
	}
}

func TestParseBatch_AttrWithUserErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"attr","key":"k","user":"alice","set":[{"path":"a","value":1}]}]`))
	if err == nil || !strings.Contains(err.Error(), `does not accept "user"`) {
		t.Errorf("err = %v, want it to mention user not accepted", err)
	}
}

func TestParseBatch_AttrWithoutSetOrRemoveErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"attr","key":"k"}]`))
	if err == nil || !strings.Contains(err.Error(), `at least one "set" or "remove"`) {
		t.Errorf("err = %v, want it to mention set/remove required", err)
	}
}

func TestParseBatch_AttrEmptySetPathErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"attr","key":"k","set":[{"path":"","value":1}]}]`))
	if err == nil || !strings.Contains(err.Error(), "empty path") {
		t.Errorf("err = %v, want it to mention empty path", err)
	}
}

func TestParseBatch_AttrEmptyRemovePathErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"attr","key":"k","remove":[""]}]`))
	if err == nil || !strings.Contains(err.Error(), "empty path") {
		t.Errorf("err = %v, want it to mention empty path", err)
	}
}

func TestParseBatch_DeleteWithoutUserErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"delete","key":"k"}]`))
	if err == nil || !strings.Contains(err.Error(), `requires "user"`) {
		t.Errorf("err = %v, want it to mention user is required", err)
	}
}

func TestParseBatch_DeleteWithValueErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"delete","key":"k","user":"alice","value":"v"}]`))
	if err == nil || !strings.Contains(err.Error(), `does not accept`) {
		t.Errorf("err = %v, want it to mention value not accepted", err)
	}
}

func TestParseBatch_RejectsWholeBatchOnSecondInvalidOp(t *testing.T) {
	// First op is valid; only the second is broken. The whole batch
	// must still be rejected up front, before any op runs.
	_, err := ParseBatch([]byte(`[{"op":"set","key":"a","value":"1"},{"op":"set","key":"b"}]`))
	if err == nil || !strings.Contains(err.Error(), "op[1]") {
		t.Errorf("err = %v, want it to identify op[1] as the failure", err)
	}
}

func TestParseBatch_SetWithRawIsValid(t *testing.T) {
	ops, err := ParseBatch([]byte(`[{"op":"set","key":"k","value":"enc:v1:AAAA","user":"alice","raw":true}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ops[0].Raw {
		t.Errorf("Raw = false, want true")
	}
}

func TestParseBatch_AttrWithRawErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"attr","key":"k","set":[{"path":"a","value":1}],"raw":true}]`))
	if err == nil || !strings.Contains(err.Error(), `does not accept "raw"`) {
		t.Errorf("err = %v, want it to mention raw not accepted", err)
	}
}

func TestParseBatch_DeleteWithRawErrors(t *testing.T) {
	_, err := ParseBatch([]byte(`[{"op":"delete","key":"k","user":"alice","raw":true}]`))
	if err == nil || !strings.Contains(err.Error(), `does not accept`) {
		t.Errorf("err = %v, want it to mention raw not accepted", err)
	}
}
