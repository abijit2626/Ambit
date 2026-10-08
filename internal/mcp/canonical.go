package mcp

import (
	"bytes"
	"encoding/json"
	"sort"
)

func canonicalJSON(raw json.RawMessage) []byte {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("null")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))

	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {

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
