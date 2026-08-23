package client

import (
	"reflect"
	"testing"
)

func TestParseAttrPath(t *testing.T) {
	got := ParseAttrPath("user.tags.0")
	want := []string{"user", "tags", "0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseAttrPath = %v, want %v", got, want)
	}
}

func TestParseAttrValue_AutoDetectsType(t *testing.T) {
	cases := []struct {
		raw  string
		want interface{}
	}{
		{"true", true},
		{"false", false},
		{"null", nil},
		{"42", float64(42)},
		{`"quoted"`, "quoted"},
		{"plainstring", "plainstring"},
		{`{"a":1}`, map[string]interface{}{"a": float64(1)}},
		{`[1,2]`, []interface{}{float64(1), float64(2)}},
	}
	for _, c := range cases {
		got := ParseAttrValue(c.raw)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseAttrValue(%q) = %#v, want %#v", c.raw, got, c.want)
		}
	}
}

func TestSetAttrPath_AddsNewTopLevelAttribute(t *testing.T) {
	doc := map[string]interface{}{"a": float64(1)}
	result, err := SetAttrPath(doc, []string{"b"}, float64(2))
	if err != nil {
		t.Fatalf("SetAttrPath returned error: %v", err)
	}
	want := map[string]interface{}{"a": float64(1), "b": float64(2)}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("result = %#v, want %#v", result, want)
	}
}

func TestSetAttrPath_ReplacesNestedLeafWhenIntermediateExists(t *testing.T) {
	doc := map[string]interface{}{
		"user": map[string]interface{}{"name": "old", "keep": float64(1)},
	}
	result, err := SetAttrPath(doc, []string{"user", "name"}, "new")
	if err != nil {
		t.Fatalf("SetAttrPath returned error: %v", err)
	}
	want := map[string]interface{}{
		"user": map[string]interface{}{"name": "new", "keep": float64(1)},
	}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("result = %#v, want %#v", result, want)
	}
}

func TestSetAttrPath_MissingIntermediateObjectErrors(t *testing.T) {
	doc := map[string]interface{}{}
	_, err := SetAttrPath(doc, []string{"a", "b", "c"}, float64(1))
	if err == nil {
		t.Fatalf("expected error setting through a missing intermediate object, got none")
	}
}

func TestSetAttrPath_ExistingScalarValueErrors(t *testing.T) {
	_, err := SetAttrPath("hello", []string{"a"}, float64(1))
	if err == nil {
		t.Fatalf("expected error setting an attribute path into a scalar, got none")
	}
}

func TestSetAttrPath_NullIntermediateErrorsMentioningNull(t *testing.T) {
	doc := map[string]interface{}{"a": nil}
	_, err := SetAttrPath(doc, []string{"a", "b"}, float64(1))
	if err == nil {
		t.Fatalf("expected error setting through a null intermediate value, got none")
	}
	if !reflect.DeepEqual(err.Error(), `path segment "b" expects an object, found null`) {
		t.Errorf("err = %q, want it to name the null type", err.Error())
	}
}

func TestSetAttrPath_ArrayReplaceInBounds(t *testing.T) {
	doc := map[string]interface{}{"tags": []interface{}{"a", "b"}}
	result, err := SetAttrPath(doc, []string{"tags", "0"}, "z")
	if err != nil {
		t.Fatalf("SetAttrPath returned error: %v", err)
	}
	want := map[string]interface{}{"tags": []interface{}{"z", "b"}}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("result = %#v, want %#v", result, want)
	}
}

func TestSetAttrPath_ArrayAppendAtLength(t *testing.T) {
	doc := map[string]interface{}{"tags": []interface{}{"a", "b"}}
	result, err := SetAttrPath(doc, []string{"tags", "2"}, "c")
	if err != nil {
		t.Fatalf("SetAttrPath returned error: %v", err)
	}
	want := map[string]interface{}{"tags": []interface{}{"a", "b", "c"}}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("result = %#v, want %#v", result, want)
	}
}

func TestSetAttrPath_ArrayOutOfBoundsGapErrors(t *testing.T) {
	doc := map[string]interface{}{"tags": []interface{}{"a", "b"}}
	_, err := SetAttrPath(doc, []string{"tags", "5"}, "x")
	if err == nil {
		t.Fatalf("expected error setting an out-of-range array index, got none")
	}
}

func TestRemoveAttrPath_RemovesTopLevelAndNestedAttribute(t *testing.T) {
	doc := map[string]interface{}{
		"a":    float64(1),
		"user": map[string]interface{}{"name": "x", "keep": float64(2)},
	}
	result, err := RemoveAttrPath(doc, []string{"a"})
	if err != nil {
		t.Fatalf("RemoveAttrPath returned error: %v", err)
	}
	result, err = RemoveAttrPath(result, []string{"user", "name"})
	if err != nil {
		t.Fatalf("RemoveAttrPath returned error: %v", err)
	}
	want := map[string]interface{}{
		"user": map[string]interface{}{"keep": float64(2)},
	}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("result = %#v, want %#v", result, want)
	}
}

func TestRemoveAttrPath_MissingPathErrors(t *testing.T) {
	doc := map[string]interface{}{"a": float64(1)}
	_, err := RemoveAttrPath(doc, []string{"missing"})
	if err == nil {
		t.Fatalf("expected error removing a path that doesn't exist, got none")
	}
}

func TestRemoveAttrPath_ArraySplicesRatherThanNullingOut(t *testing.T) {
	doc := map[string]interface{}{"tags": []interface{}{"a", "b", "c"}}
	result, err := RemoveAttrPath(doc, []string{"tags", "1"})
	if err != nil {
		t.Fatalf("RemoveAttrPath returned error: %v", err)
	}
	want := map[string]interface{}{"tags": []interface{}{"a", "c"}}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("result = %#v, want %#v (expected splice, not null-out)", result, want)
	}
}

func TestRemoveAttrPath_ArrayOutOfBoundsErrors(t *testing.T) {
	doc := map[string]interface{}{"tags": []interface{}{"a", "b"}}
	_, err := RemoveAttrPath(doc, []string{"tags", "5"})
	if err == nil {
		t.Fatalf("expected error removing an out-of-range array index, got none")
	}
}
