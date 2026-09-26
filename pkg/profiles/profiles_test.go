package profiles

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRenderParse_RoundTrip(t *testing.T) {
	values := map[string]string{
		"DB_PASSWORD": "hunter2",
		"GRAFANA":     `{"url":"https://g","auth":{"user":"x"},"list":[1,2]}`,
		"LIST":        `[1,2,3]`,
		"HTML":        `<a href="x">&</a>`,
		"MULTILINE":   "line1\nline2",
		"NOT_JSON":    "{not json",
		"NUMBER_TEXT": "8080",
		"UNICODE":     "ünïcødé ✓",
	}
	doc := RenderDoc(values)
	got, err := ParseDoc(doc)
	if err != nil {
		t.Fatalf("ParseDoc: %v\n%s", err, doc)
	}
	if !reflect.DeepEqual(got, values) {
		t.Errorf("round trip mismatch\n got %v\nwant %v\ndoc:\n%s", got, values, doc)
	}
	if !strings.Contains(string(doc), `"GRAFANA": {`+"\n"+`    "url": "https://g",`) {
		t.Errorf("JSON value not pretty-printed as nested JSON:\n%s", doc)
	}
	if strings.Contains(string(doc), "\\"+"u003c") {
		t.Errorf("HTML characters escaped:\n%s", doc)
	}
}

func TestRenderDoc_Empty(t *testing.T) {
	doc := RenderDoc(nil)
	if got, err := ParseDoc(doc); err != nil || len(got) != 0 {
		t.Errorf("empty doc %q → %v, %v", doc, got, err)
	}
}

func TestParseDoc_NonStringValuesStoredAsCompactJSON(t *testing.T) {
	got, err := ParseDoc([]byte(`{"PORT": 8080, "ON": true, "CFG": { "a" : [1, 2] }, "N": null}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"PORT": "8080", "ON": "true", "CFG": `{"a":[1,2]}`, "N": "null"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseDoc_Errors(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"duplicate key":   {"{\n  \"A\": \"1\",\n  \"A\": \"2\"\n}", `line 3: duplicate key "A"`},
		"missing comma":   {"{\n  \"A\": \"1\"\n  \"B\": \"2\"\n}", "line 3"},
		"trailing comma":  {"{\n  \"A\": \"1\",\n}", "line 2: trailing comma"},
		"empty value":     {`{"A": ""}`, "empty value"},
		"empty key":       {`{"": "x"}`, "empty key"},
		"not an object":   {`["A"]`, "must be a JSON object"},
		"trailing data":   {`{"A": "1"} {}`, "after the closing"},
		"unterminated":    {"{\n  \"A\": \"1\"\n", "unexpected end"},
		"empty document":  {"", "unexpected end"},
		"control in key":  {`{"A\u0001": "1"}`, "control characters"},
		"unquoted string": {`{"A": hello}`, "line 1"},
	}
	for name, tc := range cases {
		_, err := ParseDoc([]byte(tc.doc))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
}

func TestMergeEdit_KeepsUntouchedValuesExactly(t *testing.T) {
	previous := map[string]string{
		"SPACED": `[1, 2]`,         // renders/parses to "[1,2]"
		"OBJ":    `{"b":1, "a":2}`, // key order kept, spacing not
		"PLAIN":  "x",
	}
	edited, err := ParseDoc(RenderDoc(previous))
	if err != nil {
		t.Fatal(err)
	}
	if merged := MergeEdit(previous, edited); !reflect.DeepEqual(merged, previous) {
		t.Errorf("unedited round trip changed values: %v", merged)
	}

	edited["PLAIN"] = "y"
	edited["SPACED"] = "[1,2,3]"
	merged := MergeEdit(previous, edited)
	if merged["PLAIN"] != "y" || merged["SPACED"] != "[1,2,3]" || merged["OBJ"] != previous["OBJ"] {
		t.Errorf("merged = %v", merged)
	}
}

func TestChanges(t *testing.T) {
	p := New("https://v", "alice")
	p.Base = map[string]KeyState{"same": {Value: "1"}, "changed": {Value: "old"}, "removed": {Value: "x"}}
	p.Values = map[string]string{"same": "1", "changed": "new", "added": "a"}

	var got []string
	for _, ch := range p.Changes() {
		got = append(got, ch.Kind.Symbol()+ch.Key+":"+ch.Old+">"+ch.New)
	}
	if strings.Join(got, ",") != "+added:>a,~changed:old>new,-removed:x>" {
		t.Errorf("Changes = %v", got)
	}
}

func TestSaveLoad_EncryptedAndBound(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profiles")
	dataKey := bytes.Repeat([]byte{9}, 32)
	p := New("https://v", "alice")
	p.Values["DB_PASSWORD"] = "hunter2"
	p.Base["DB_PASSWORD"] = KeyState{Value: "hunter2", Remote: RemoteHash("enc"), Encrypted: true}
	if err := Save(dir, dataKey, p); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(Path(dir, "alice"))
	for _, leak := range []string{"hunter2", "DB_PASSWORD", RemoteHash("enc")} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("profile file leaks %q", leak)
		}
	}

	got, err := Load(dir, dataKey, "https://v", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Errorf("Load = %+v, want %+v", got, p)
	}

	if _, err := Load(dir, bytes.Repeat([]byte{8}, 32), "https://v", "alice"); err == nil {
		t.Error("opened with the wrong data key")
	}
	if _, err := Load(dir, dataKey, "https://other", "alice"); err == nil {
		t.Error("opened for another endpoint")
	}
	os.Rename(Path(dir, "alice"), Path(dir, "bob"))
	if _, err := Load(dir, dataKey, "https://v", "bob"); err == nil {
		t.Error("alice's file opened as bob's")
	}
}

func TestListLocalAndValidateUser(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"bob.json.enc", "alice.json.enc", ".tmp-x", "notes.txt"} {
		os.WriteFile(filepath.Join(dir, name), nil, 0600)
	}
	users, err := ListLocal(dir)
	if err != nil || !reflect.DeepEqual(users, []string{"alice", "bob"}) {
		t.Errorf("ListLocal = %v, %v", users, err)
	}
	for _, bad := range []string{"", ".", "..", ".hidden", "a/b", `a\b`} {
		if ValidateUser(bad) == nil {
			t.Errorf("ValidateUser(%q) = nil", bad)
		}
	}
}
