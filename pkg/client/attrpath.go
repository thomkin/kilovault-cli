package client

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ParseAttrPath splits a dot-separated attribute path into segments,
// e.g. "user.tags.0" -> ["user", "tags", "0"].
func ParseAttrPath(path string) []string {
	return strings.Split(path, ".")
}

// ParseAttrValue auto-detects the type of a --set value: valid JSON
// (bool/number/null/quoted string/object/array) is parsed as JSON;
// anything that fails to parse is stored as a raw string.
func ParseAttrValue(raw string) interface{} {
	var v interface{}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	return v
}

func parseIndex(seg string) (int, bool) {
	idx, err := strconv.Atoi(seg)
	if err != nil {
		return 0, false
	}
	return idx, true
}

func typeName(v interface{}) string {
	if v == nil {
		return "null"
	}
	switch v.(type) {
	case map[string]interface{}:
		return "object"
	case []interface{}:
		return "array"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// SetAttrPath sets value at path inside node (a decoded JSON document:
// map[string]interface{} / []interface{} / scalar). Every non-leaf
// segment must already resolve to an existing container of the right
// type — SetAttrPath never creates missing intermediate containers,
// only the final (leaf) key/index may be new. Array segments (numeric)
// may target an existing index (replace) or exactly len(array)
// (append); anything else is an out-of-range error.
func SetAttrPath(node interface{}, path []string, value interface{}) (interface{}, error) {
	seg, rest := path[0], path[1:]

	if idx, isIdx := parseIndex(seg); isIdx {
		arr, ok := node.([]interface{})
		if !ok {
			return nil, fmt.Errorf("path segment %q expects an array, found %s", seg, typeName(node))
		}
		if idx < 0 || idx > len(arr) {
			return nil, fmt.Errorf("array index %d out of range (length %d)", idx, len(arr))
		}
		if len(rest) == 0 {
			if idx == len(arr) {
				return append(arr, value), nil
			}
			arr[idx] = value
			return arr, nil
		}
		if idx == len(arr) {
			return nil, fmt.Errorf("path segment %q does not exist", seg)
		}
		child, err := SetAttrPath(arr[idx], rest, value)
		if err != nil {
			return nil, err
		}
		arr[idx] = child
		return arr, nil
	}

	obj, ok := node.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("path segment %q expects an object, found %s", seg, typeName(node))
	}
	if len(rest) == 0 {
		obj[seg] = value
		return obj, nil
	}
	child, exists := obj[seg]
	if !exists {
		return nil, fmt.Errorf("path segment %q does not exist", seg)
	}
	updated, err := SetAttrPath(child, rest, value)
	if err != nil {
		return nil, err
	}
	obj[seg] = updated
	return obj, nil
}

// RemoveAttrPath deletes the attribute/element at path inside node.
// Every segment (including the leaf) must already exist; removing an
// absent key or an out-of-range index is an error. Removing an array
// element splices it out (shifts later elements down), it does not
// null it out.
func RemoveAttrPath(node interface{}, path []string) (interface{}, error) {
	seg, rest := path[0], path[1:]

	if idx, isIdx := parseIndex(seg); isIdx {
		arr, ok := node.([]interface{})
		if !ok {
			return nil, fmt.Errorf("path segment %q expects an array, found %s", seg, typeName(node))
		}
		if idx < 0 || idx >= len(arr) {
			return nil, fmt.Errorf("array index %d out of range (length %d)", idx, len(arr))
		}
		if len(rest) == 0 {
			return append(arr[:idx:idx], arr[idx+1:]...), nil
		}
		child, err := RemoveAttrPath(arr[idx], rest)
		if err != nil {
			return nil, err
		}
		arr[idx] = child
		return arr, nil
	}

	obj, ok := node.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("path segment %q expects an object, found %s", seg, typeName(node))
	}
	child, exists := obj[seg]
	if !exists {
		return nil, fmt.Errorf("path segment %q does not exist", seg)
	}
	if len(rest) == 0 {
		delete(obj, seg)
		return obj, nil
	}
	updated, err := RemoveAttrPath(child, rest)
	if err != nil {
		return nil, err
	}
	obj[seg] = updated
	return obj, nil
}
