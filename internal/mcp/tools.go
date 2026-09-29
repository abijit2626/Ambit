package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/abijit2626/ambit/internal/event"
)

// HashPrefix labels the metadata hash so nobody mistakes it for one of the keyed
// digests the rest of the schema carries.
//
// The metadata hash is deliberately **unkeyed**, unlike every path and content
// digest in internal/features. Three reasons, in order of weight:
//
//  1. The interposer holds no key. It runs as the developer, as a child of the
//     agent process, while the HMAC key is owned by ambitd and readable only by
//     it. Handing the key to a process the agent spawns would put it inside the
//     blast radius the key exists to bound.
//  2. What is hashed is the server's own advertised metadata, not our content. A
//     tool description published by a third-party MCP server is not ours to
//     protect, and the server *name* already crosses in cleartext.
//  3. An unkeyed hash compares across endpoints, across orgs and across an MSSP's
//     customers. Two endpoints reporting different hashes for the same server and
//     version is itself a detection signal, and a keyed hash would destroy it.
//
// The residual is real and accepted: for an internal server, an analyst holding
// the hash can confirm a guess about a tool description. That is a weak oracle
// against someone who, by the time they are reading our alert stream, can also
// just call the tool.
const HashPrefix = "sha256:"

// hashLen truncates the hex digest. 32 hex characters is 128 bits, which is
// ample for collision resistance against a non-adversarial-collision use — we
// compare a value against its own previous value — and keeps the field narrow
// in an event budget measured in fields and bytes.
const hashLen = 32

// Tool is one entry from a tools/list result.
//
// Annotations reuses event.Annotations rather than defining a parallel type: its
// field tags are already the MCP wire names, and its pointer-per-hint shape is
// there precisely because a missing hint must never be read as false. See the
// comment on that type.
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

// EventAnnotations projects the tool's annotations onto the schema type.
//
// Absent annotations produce an empty set of nil pointers, which is the correct
// reading: the server said nothing, which is not the same as the server saying
// false, and only the nil case is safe to treat as "no claim".
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

// Listing is a tools/list result.
//
// NextCursor being non-empty means this is one page of several. That matters more
// than it looks: comparing a single page against a full baseline would report
// every tool not on that page as removed, so the caller must accumulate pages
// until a page arrives without a cursor before drawing any conclusion about
// removals. See internal/interpose.
type Listing struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// ParseToolsList decodes a tools/list result.
func ParseToolsList(result json.RawMessage) (Listing, error) {
	var l Listing
	if err := json.Unmarshal(result, &l); err != nil {
		return Listing{}, err
	}
	return l, nil
}

// Field names used in drift reporting. They are the SIEM-visible vocabulary for
// "what about this tool changed", so they are stable strings rather than derived
// from Go field names.
const (
	FieldName         = "name"
	FieldTitle        = "title"
	FieldDescription  = "description"
	FieldInputSchema  = "input_schema"
	FieldOutputSchema = "output_schema"
	FieldAnnotations  = "annotations"
)

// MetadataHash is the D4 comparison value: a hash over the tool's name,
// description and input schema, as docs/02-architecture.md specifies.
//
// Annotations, title and output schema are deliberately *not* in this hash but
// are tracked separately by the baseline (see FieldDigests). Keeping the
// documented three in the headline hash means the number in an alert means what
// the design says it means; tracking the rest separately means a server flipping
// destructiveHint from true to false — a policy-relevant change with no effect on
// the description — still reports as drift.
func MetadataHash(t Tool) string {
	h := sha256.New()
	h.Write([]byte("ambit.mcp.tool.v1\n"))
	writeField(h, FieldName, []byte(t.Name))
	writeField(h, FieldDescription, []byte(t.Description))
	writeField(h, FieldInputSchema, canonicalJSON(t.InputSchema))
	return HashPrefix + hex.EncodeToString(h.Sum(nil))[:hashLen]
}

// FieldDigests returns a per-field digest so drift can name what changed rather
// than only that something did. A runbook that says "the description changed" is
// actionable by an analyst who cannot see our source tree; "the hash changed" is
// not.
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

// ChangedFields compares two field-digest maps and returns the field names that
// differ, sorted. A field present in one map and absent from the other counts as
// changed: that is a schema-version difference in our own code, and reporting it
// is better than silently treating it as equal.
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

// writeField length-prefixes each field so concatenation cannot be gamed: a tool
// named "ab" described as "c" must not hash the same as one named "a" described
// as "bc".
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
