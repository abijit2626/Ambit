package mcp

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The interposer's whole promise is that putting it in front of a server changes nothing on the wire.
func FuzzRelayIsByteExact(f *testing.F) {
	f.Add([]byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n"), false)
	f.Add([]byte("no newline at the end"), true)
	f.Add([]byte("\n\n\r\n{}\n"), false)
	f.Add([]byte{0, 0xff, '\n', 0x80}, true)
	f.Fuzz(func(t *testing.T, in []byte, observeFirst bool) {
		order := ForwardFirst
		if observeFirst {
			order = ObserveFirst
		}
		var out bytes.Buffer
		var seen int
		err := Relay(&out, bytes.NewReader(in), order, func(fr Frame) { seen += len(fr.Raw) })
		if err != nil {
			t.Fatalf("Relay returned %v on an in-memory reader", err)
		}
		if !bytes.Equal(out.Bytes(), in) {
			t.Fatalf("relay changed the stream:\nin  %q\nout %q", in, out.Bytes())
		}
		if seen != len(in) {
			t.Fatalf("observer saw %d bytes of %d: every byte must reach the analyzer", seen, len(in))
		}
	})
}

// The canonical form is what MetadataHash hashes, so it must be a fixed point: hashing an already
// canonical description must not move the hash.
func FuzzCanonicalJSONIsAFixedPoint(f *testing.F) {
	f.Add([]byte(`{"b":1,"a":[true,null,"x"],"c":{"z":1.50,"y":"é"}}`))
	f.Add([]byte(`"plain"`))
	f.Add([]byte(`1e400`))
	f.Add([]byte(`{"a":"<>& "}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if !json.Valid(raw) {
			return
		}
		once := canonicalJSON(raw)
		twice := canonicalJSON(once)
		if !bytes.Equal(once, twice) {
			t.Fatalf("canonical form is not stable:\nin    %q\nonce  %q\ntwice %q", raw, once, twice)
		}
	})
}

func FuzzParseNeverPanics(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","description":"b","inputSchema":{}}]}}`))
	f.Add([]byte(`[{"jsonrpc":"2.0"}]`))
	f.Add([]byte(`{"result":{"tools":[{"name":1}]}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := Parse(raw)
		if err != nil || m == nil {
			return
		}
		_ = m.IsResponse()
		_ = m.IsNotification()
		_ = m.IDKey()
		if l, err := ParseToolsList(m.Result); err == nil {
			for _, tool := range l.Tools {
				if MetadataHash(tool) != MetadataHash(tool) {
					t.Fatal("MetadataHash is not deterministic")
				}
			}
		}
	})
}
