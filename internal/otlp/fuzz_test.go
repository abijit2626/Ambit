package otlp

import "testing"

// Whatever arrives on the OTLP port, decoding must not panic.
func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add(uint8(0), []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[{"key":"session.id","value":{"stringValue":"s1"}}]}]}]}]}`))
	f.Add(uint8(1), []byte(`{"resourceMetrics":[{"scopeMetrics":[{"metrics":[{"name":"x","sum":{"dataPoints":[{"asInt":"3"}]}}]}]}]}`))
	f.Add(uint8(2), []byte(`{"resourceSpans":[]}`))
	f.Add(uint8(0), []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[{"key":"k","value":{"arrayValue":{"values":[{"kvlistValue":{}}]}}}]}]}]}]}`))
	sigs := []Signal{SignalLogs, SignalMetrics, SignalTraces}
	f.Fuzz(func(t *testing.T, which uint8, body []byte) {
		recs, err := Decode(sigs[int(which)%len(sigs)], body)
		if err != nil {
			return
		}
		for _, r := range recs {
			_ = r.SessionID()
			_ = r.Attr("tool_name", "event.name")
		}
	})
}
