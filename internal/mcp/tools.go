package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/abijit2626/ambit/internal/event"
)

const HashPrefix = "sha256:"

const hashLen = 32

type Tool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  *struct {
		Title           string `json:"title,omitempty"`
		ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
		DestructiveHint *bool  `json:"destructiveHint,omitempty"`
		IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
		OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
	} `json:"annotations,omitempty"`
}

func (t Tool) EventAnnotations() event.Annotations {
	if t.Annotations == nil {
		return event.Annotations{}
	}
	return event.Annotations{
		ReadOnlyHint:    t.Annotations.ReadOnlyHint,
		DestructiveHint: t.Annotations.DestructiveHint,
		IdempotentHint:  t.Annotations.IdempotentHint,
		OpenWorldHint:   t.Annotations.OpenWorldHint,
	}
}

type Listing struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

func ParseToolsList(result json.RawMessage) (Listing, error) {
	var l Listing
	if err := json.Unmarshal(result, &l); err != nil {
		return Listing{}, err
	}
	return l, nil
}

const (
	FieldName         = "name"
	FieldTitle        = "title"
	FieldDescription  = "description"
	FieldInputSchema  = "input_schema"
	FieldOutputSchema = "output_schema"
	FieldAnnotations  = "annotations"
)

func MetadataHash(t Tool) string {
	h := sha256.New()
	h.Write([]byte("ambit.mcp.tool.v1\n"))
	writeField(h, FieldName, []byte(t.Name))
	writeField(h, FieldDescription, []byte(t.Description))
	writeField(h, FieldInputSchema, canonicalJSON(t.InputSchema))
	return HashPrefix + hex.EncodeToString(h.Sum(nil))[:hashLen]
}

func FieldDigests(t Tool) map[string]string {
	annotations := []byte("null")
	if t.Annotations != nil {
		if enc, err := json.Marshal(t.Annotations); err == nil {
			annotations = canonicalJSON(enc)
		}
	}
	return map[string]string{
		FieldName:         fieldDigest(FieldName, []byte(t.Name)),
		FieldTitle:        fieldDigest(FieldTitle, []byte(t.Title)),
		FieldDescription:  fieldDigest(FieldDescription, []byte(t.Description)),
		FieldInputSchema:  fieldDigest(FieldInputSchema, canonicalJSON(t.InputSchema)),
		FieldOutputSchema: fieldDigest(FieldOutputSchema, canonicalJSON(t.OutputSchema)),
		FieldAnnotations:  fieldDigest(FieldAnnotations, annotations),
	}
}

func ChangedFields(old, new map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for k, v := range new {
		seen[k] = true
		if old[k] != v {
			out = append(out, k)
		}
	}
	for k := range old {
		if !seen[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func fieldDigest(name string, value []byte) string {
	h := sha256.New()
	h.Write([]byte("ambit.mcp.field.v1\n"))
	writeField(h, name, value)
	return HashPrefix + hex.EncodeToString(h.Sum(nil))[:hashLen]
}

func writeField(h interface{ Write([]byte) (int, error) }, name string, value []byte) {
	var lenBuf [8]byte
	n := uint64(len(value))
	for i := 0; i < 8; i++ {
		lenBuf[i] = byte(n >> (8 * (7 - i)))
	}
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(value)
}
