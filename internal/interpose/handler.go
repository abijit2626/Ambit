package interpose

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

// maxReportBytes bounds an inbound report. A listing of several hundred tools with
// long descriptions is still well inside this; the bound exists because the
// endpoint accepts input from a process the agent spawns.
const maxReportBytes = 8 << 20

// NewHandler returns the ambitd-side endpoint for interposer reports.
//
// sink must not block: it is called on the HTTP handler's goroutine, which shares
// a listener with the hook path and its latency budget.
func NewHandler(sink func(*Report), log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxReportBytes))
		if err != nil {
			log.Warn("interpose report read failed", "err", err)
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		var rep Report
		if err := json.Unmarshal(body, &rep); err != nil {
			log.Warn("interpose report parse failed", "err", err, "bytes", len(body))
			http.Error(w, "parse failed", http.StatusBadRequest)
			return
		}
		if rep.SchemaV != ReportSchemaVersion {
			// Loud rather than best-effort: a version skew that silently produced
			// empty findings would look exactly like a server with nothing to
			// report.
			log.Warn("interpose report schema mismatch",
				"got", rep.SchemaV, "want", ReportSchemaVersion, "server", rep.Server)
		}
		if rep.Server == "" {
			http.Error(w, "server is required", http.StatusBadRequest)
			return
		}
		if sink != nil {
			sink(&rep)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
