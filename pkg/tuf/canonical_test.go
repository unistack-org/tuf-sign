package tuf

import (
	"strings"
	"testing"
)

// Golden vectors from the TUF specification (KMD-0006 canonical JSON).
func TestCanonicalGolden(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{`{ "a" : 1 }`, `{"a":1}`},
		{`{"a":[1,2,3]}`, `{"a":[1,2,3]}`},
		{`{"a":{}}`, `{"a":{}}`},
		{`{"a":[]}`, `{"a":[]}`},
		{`{"a":null}`, `{"a":null}`},
		{`{"a":true,"b":false}`, `{"a":true,"b":false}`},
		// spaces around separators are removed
		{`[ 1 , 2 ]`, `[1,2]`},
		// forward slash is NOT escaped in canonical JSON
		{`{"a":"http://x/y"}`, `{"a":"http://x/y"}`},
		// control characters use 4-hex \u escapes, uppercase hex
		{`{"a":"\u0000"}`, `{"a":"\u0000"}`},
		{`{"a":"\u001f"}`, `{"a":"\u001f"}`},
		// DEL is escaped
		{`{"a":"\u007f"}`, `{"a":"\u007f"}`},
		// U+2028/U+2029 escaped
		{`{"a":"\u2028\u2029"}`, `{"a":"\u2028\u2029"}`},
		// backspace, tab, newline, CR, quote, backslash keep short escapes
		{`{"a":"\b\t\n\f\r\"\\"}`, `{"a":"\b\t\n\f\r\"\\"}`},
		// non-ASCII printable is preserved verbatim (UTF-8)
		{`{"a":"привет"}`, `{"a":"привет"}`},
		// numbers: no exponent, no plus, no leading zeros, no trailing .0
		{`{"a":1e2}`, `{"a":100.0}`},
		{`{"a":1.0}`, `{"a":1.0}`},
		{`{"a":-0}`, `{"a":0}`},
		{`{"a":-0.0}`, `{"a":-0.0}`},
		{`{"a":1.5e-3}`, `{"a":0.0015}`},
		// nested key ordering is recursive
		{`{"z":{"b":1,"a":2},"a":{"d":1,"c":2}}`, `{"a":{"c":2,"d":1},"z":{"a":2,"b":1}}`},
	}
	for _, c := range cases {
		got, err := Canonicalize([]byte(c.in))
		if err != nil {
			t.Errorf("Canonicalize(%s): %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("Canonicalize(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestCanonicalRejects(t *testing.T) {
	bad := []string{
		`{"a":1,"a":2}`,  // duplicate keys
		`{"a":1e999}`,    // out of range float
		`{"a":1,`,        // truncated
		`{"a":1}{"b":2}`, // trailing value
	}
	for _, in := range bad {
		if _, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("Canonicalize(%s): expected error", in)
		}
	}
}

func TestCanonicalIdempotent(t *testing.T) {
	in := []byte(`{"b":1,"a":[3,2,1],"z":{"n":1.5,"m":-10}}`)
	once, err := Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := Canonicalize(once)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Fatalf("not idempotent: %s vs %s", once, twice)
	}
	if !strings.Contains(string(once), `"m":-10`) {
		t.Fatalf("negative number lost: %s", once)
	}
}

func TestMarshalCanonical(t *testing.T) {
	type inner struct {
		B int `json:"b"`
		A int `json:"a"`
	}
	type outer struct {
		Z inner  `json:"z"`
		A []int  `json:"a"`
		N string `json:"n"`
	}
	got, err := MarshalCanonical(outer{Z: inner{B: 1, A: 2}, A: []int{1, 2}, N: "x"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":[1,2],"n":"x","z":{"a":2,"b":1}}`
	if string(got) != want {
		t.Fatalf("MarshalCanonical = %s, want %s", got, want)
	}
}
