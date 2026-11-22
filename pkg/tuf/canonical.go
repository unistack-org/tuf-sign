package tuf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize takes arbitrary JSON bytes and returns them in TUF
// canonical form (KMD-0006 / LZW-style): object keys sorted
// lexicographically, no insignificant whitespace, minimal escaping,
// integers rendered without exponent. Duplicate object keys are
// rejected.
func Canonicalize(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("tuf: trailing data after JSON value")
	}
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalCanonical marshals v (any JSON-serialisable Go value) into
// TUF canonical JSON. time.Time values render as RFC 3339 strings.
func MarshalCanonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("tuf: expected object key")
				}
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("tuf: duplicate key %q in canonical JSON", k)
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := dec.Token(); err != nil { // consume }
				return nil, err
			}
			return m, nil
		case '[':
			a := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil { // consume ]
				return nil, err
			}
			return a, nil
		default:
			return nil, fmt.Errorf("tuf: unexpected delimiter %q", t)
		}
	case json.Number:
		return t, nil
	case string, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("tuf: unexpected token %T", tok)
	}
}

func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, v)
	case json.Number:
		return writeCanonicalNumber(buf, v)
	case []any:
		buf.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := encodeCanonical(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("tuf: cannot canonically encode %T", v)
	}
	return nil
}

// writeCanonicalString quotes s escaping exactly what the canonical
// form requires: quotation mark, reverse solidus, C0 controls, DEL,
// U+2028, U+2029 and lone surrogates (Python canonicaljson /
// KMD-0006 rules). All other code points are emitted raw as UTF-8.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r < 0x20, r == 0x7f, r == 0x2028, r == 0x2029:
			fmt.Fprintf(buf, `\u%04x`, r)
		case r >= 0x80 && utf16.IsSurrogate(r):
			fmt.Fprintf(buf, `\u%04x`, r)
		case r == utf8.RuneError:
			// Invalid UTF-8 byte: emit the replacement char escaped.
			buf.WriteString(`\ufffd`)
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// writeCanonicalNumber renders a number deterministically: int64
// as-is, floats in Go's shortest round-trip form, no exponents for
// integers.
func writeCanonicalNumber(buf *bytes.Buffer, n json.Number) error {
	s := n.String()
	isFloat := strings.ContainsAny(s, ".eE")
	if !isFloat {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			buf.WriteString(strconv.FormatInt(i, 10))
			return nil
		}
		if u, err := strconv.ParseUint(s, 10, 64); err == nil {
			buf.WriteString(strconv.FormatUint(u, 10))
			return nil
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("tuf: invalid number %q", s)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return fmt.Errorf("tuf: non-finite number %q", s)
	}
	out := strconv.FormatFloat(f, 'g', -1, 64)
	// Canonical floats keep a decimal point (Python canonicaljson
	// renders 100.0 as "100.0", not "100").
	if !strings.ContainsAny(out, ".e") {
		out += ".0"
	}
	// No "+" in exponents, lowercase 'e'.
	out = strings.ReplaceAll(out, "e+", "e")
	buf.WriteString(out)
	return nil
}
