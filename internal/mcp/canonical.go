package mcp

import (
	"bytes"
	"encoding/json"
	"sort"
)

// canonicalJSON re-encodes arbitrary JSON deterministically: object keys sorted,
// no insignificant whitespace, number literals preserved.
//
// This exists because the metadata hash must be stable across cosmetic changes
// that carry no meaning. A server that reorders its schema keys between two
// startups — which happens whenever a schema is built from a map, in any
// language — would otherwise produce a different hash every time, and D4 would
// alert on noise until someone turned it off. The inverse failure matters more:
// a hash that ignored ordering *and* content would miss a real change.
//
// Array order is preserved. In JSON Schema, `required` and `enum` ordering is not
// semantically significant but `prefixItems` is, and guessing per keyword would
// be a semantic model of JSON Schema that this package has no business carrying.
// Sorting nothing is the conservative choice: a reordered `required` reports as
// drift, which is a false positive an analyst can dismiss, rather than a missed
// change.
//
// Duplicate keys in the input resolve last-wins, matching encoding/json.
func canonicalJSON(raw json.RawMessage) []byte {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("null")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber keeps 1.0 distinct from 1 and avoids float rounding making two
	// different schemas hash the same.
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		// Unparseable metadata is hashed verbatim rather than dropped: whatever
		// this is, a change to it is still a change worth noticing.
		return raw
	}
	var buf bytes.Buffer
	writeCanonical(&buf, v)
	return buf.Bytes()
}

func writeCanonical(buf *bytes.Buffer, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			writeCanonical(buf, t[k])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonical(buf, e)
		}
		buf.WriteByte(']')
	case string:
		writeString(buf, t)
	case json.Number:
		buf.WriteString(t.String())
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	default:
		// Unreachable for output of encoding/json with UseNumber, but a panic
		// here would take down a developer's MCP server.
		enc, err := json.Marshal(t)
		if err != nil {
			buf.WriteString("null")
			return
		}
		buf.Write(enc)
	}
}

func writeString(buf *bytes.Buffer, s string) {
	enc, err := json.Marshal(s)
	if err != nil {
		buf.WriteString(`""`)
		return
	}
	buf.Write(enc)
}
