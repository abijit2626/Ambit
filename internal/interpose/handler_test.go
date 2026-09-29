package interpose

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postReport(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestHandlerAcceptsAReport(t *testing.T) {
	var got *Report
	h := NewHandler(func(rep *Report) { got = rep }, quietLogger())

	rep := Report{SchemaV: ReportSchemaVersion, Server: "wiki", Trigger: TriggerToolsList,
		Tools: []ToolReport{{Tool: "search", State: "new", MetadataHash: "sha256:abc"}}}
	body, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	rr := postReport(t, h, string(body))
	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if got == nil || got.Server != "wiki" || len(got.Tools) != 1 {
		t.Fatalf("sink got %+v", got)
	}
	if got.Tools[0].MetadataHash != "sha256:abc" {
		t.Errorf("tool report mangled: %+v", got.Tools[0])
	}
}

func TestHandlerRejectsBadInput(t *testing.T) {
	h := NewHandler(func(*Report) { t.Error("sink must not be called for a rejected report") }, quietLogger())

	t.Run("wrong method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, Path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		if rr := postReport(t, h, `{"server":`); rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("missing server", func(t *testing.T) {
		// Without a server name the report cannot be turned into an event that
		// names a tool, so it is refused rather than recorded against nothing.
		if rr := postReport(t, h, `{"schema_v":1,"trigger":"tools_list"}`); rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}

// TestHandlerAcceptsASchemaMismatchLoudly: a version skew must not present as a
// server with nothing to report, so the report is still delivered and the mismatch
// is logged.
func TestHandlerAcceptsASchemaMismatchLoudly(t *testing.T) {
	var logged bytes.Buffer
	var got *Report
	h := NewHandler(func(rep *Report) { got = rep }, testLogger(&logged))

	rr := postReport(t, h, `{"schema_v":99,"server":"wiki","trigger":"tools_list"}`)
	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if got == nil {
		t.Fatal("report was dropped on a version mismatch")
	}
	if !strings.Contains(logged.String(), "schema mismatch") {
		t.Errorf("mismatch was not logged: %q", logged.String())
	}
}

func TestHandlerBoundsTheBody(t *testing.T) {
	var got *Report
	h := NewHandler(func(rep *Report) { got = rep }, quietLogger())
	// A body past the bound is truncated by the limit reader, so it fails to parse
	// rather than being buffered without limit.
	huge := `{"schema_v":1,"server":"wiki","pad":"` + strings.Repeat("x", maxReportBytes+1024) + `"}`
	if rr := postReport(t, h, huge); rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if got != nil {
		t.Error("an oversized body should not reach the sink")
	}
}
