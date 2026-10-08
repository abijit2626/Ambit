package mcp

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

const maxSchemaText = 64 << 10

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

func SchemaText(raw json.RawMessage) (text string, truncated bool) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {

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
