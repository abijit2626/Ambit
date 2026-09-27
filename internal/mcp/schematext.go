package mcp

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// maxSchemaText bounds the text handed to the D5 scanner. A hostile server can
// send a megabyte of schema; the regex pass over it happens on the relay's
// analysis path, and an unbounded scan there is a latency hazard for the
// developer's tool calls. Truncation is reported by the caller as a schema that
// was only partly scanned rather than silently accepted.
const maxSchemaText = 64 << 10

// schemaKeywords are JSON Schema structural keys. Their names are skipped when
// collecting text: matching a rule against the literal word "description" or
// "properties" would be noise on every tool in the fleet. Their *values* are
// still collected, which is the point — a poisoned tool hides its instructions in
// a parameter description.
var schemaKeywords = map[string]bool{
	"$schema": true, "$id": true, "$ref": true, "$defs": true, "$comment": true,
	"type": true, "properties": true, "required": true, "items": true,
	"prefixItems": true, "additionalProperties": true, "patternProperties": true,
	"enum": true, "const": true, "default": true, "examples": true,
	"description": true, "title": true, "format": true, "pattern": true,
	"minimum": true, "maximum": true, "exclusiveMinimum": true, "exclusiveMaximum": true,
	"minLength": true, "maxLength": true, "minItems": true, "maxItems": true,
	"uniqueItems": true, "anyOf": true, "allOf": true, "oneOf": true, "not": true,
	"definitions": true, "nullable": true, "readOnly": true, "writeOnly": true,
	"deprecated": true,
}

// SchemaText flattens a tool schema to the text D5 should scan: every string
// value, plus property names that are not JSON Schema keywords.
//
// Property names are included because the model reads them too: a parameter named
// `send_credentials_to_url` is metadata that shapes behavior exactly like a
// description does. Truncated reports whether the bound was hit.
func SchemaText(raw json.RawMessage) (text string, truncated bool) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		// Unparseable schema: scan the raw bytes rather than nothing. Whatever it
		// is, the model was offered it.
		return clip(string(raw))
	}
	var b strings.Builder
	collectText(&b, v)
	return clip(b.String())
}

func clip(s string) (string, bool) {
	if len(s) > maxSchemaText {
		return s[:maxSchemaText], true
	}
	return s, false
}

func collectText(b *strings.Builder, v any) {
	if b.Len() > maxSchemaText {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// Sorted so the same schema always produces the same text, which keeps
		// findings stable between two listings that differ only in key order.
		sort.Strings(keys)
		for _, k := range keys {
			if !schemaKeywords[k] {
				b.WriteString(k)
				b.WriteByte('\n')
			}
			collectText(b, t[k])
		}
	case []any:
		for _, e := range t {
			collectText(b, e)
		}
	case string:
		b.WriteString(t)
		b.WriteByte('\n')
	}
}
