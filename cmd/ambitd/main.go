package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abijit2626/ambit/internal/collector"
	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/doctor"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/features"
	"github.com/abijit2626/ambit/internal/hook"
	"github.com/abijit2626/ambit/internal/hookfwd"
	"github.com/abijit2626/ambit/internal/interpose"
	"github.com/abijit2626/ambit/internal/m0report"
	"github.com/abijit2626/ambit/internal/otlp"
	"github.com/abijit2626/ambit/internal/runstate"
	"github.com/abijit2626/ambit/internal/sink"
)

var version = "0.0.0-dev"

func main() {
	// A command hook, not the daemon: Claude Code runs this for SessionStart, which it does not
	// deliver to hooks of type http. See internal/hookfwd.
	if len(os.Args) > 1 && os.Args[1] == "hook-forward" {
		os.Exit(hookfwd.Main(os.Args[2:], os.Stdin, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "doctor" {
		os.Exit(doctor.Main(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "report" {
		os.Exit(m0report.Main(os.Args[2:], os.Stdout, os.Stderr))
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ambitd:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "", "path to config JSON (defaults apply when absent)")
		printConfig = flag.Bool("print-config", false, "print the effective configuration and exit")
		showVersion = flag.Bool("version", false, "print version and exit")
		verbose     = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *printConfig {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cfg)
	}

	if cfg.Enforce {
		return errors.New("enforce is true but no policy engine exists in M0; " +
			"set enforce=false or deploy a build that implements the gate")
	}

	key, err := config.LoadOrCreateFingerprintKey(cfg.FingerprintKeyPath, func() ([]byte, error) {
		b := make([]byte, 32)
		_, err := rand.Read(b)
		return b, err
	})
	if err != nil {
		return err
	}

	eventsOpts := sink.DefaultOptions(cfg.EventsPath)
	eventsOpts.MaxBytes, eventsOpts.MaxFiles = cfg.EventsMaxBytes, cfg.EventsMaxFiles
	events, err := sink.Open(eventsOpts)
	if err != nil {
		return err
	}
	defer events.Close()

	trajOpts := sink.DefaultOptions(cfg.TrajectoryPath)
	trajOpts.MaxBytes, trajOpts.MaxFiles = cfg.TrajectoryMaxBytes, cfg.TrajectoryMaxFiles
	traj, err := sink.Open(trajOpts)
	if err != nil {
		return err
	}
	defer traj.Close()

	coll := collector.New(collector.Options{
		Config:         cfg,
		EventsSink:     events,
		TrajectorySink: traj,
		Extractor:      features.New(key),
		Logger:         log,
		Version:        version,
	})

	srv, err := hook.NewServer(hook.Options{
		Addr:    cfg.HookAddr,
		Handler: coll,

		Extra: map[string]http.Handler{
			interpose.Path: interpose.NewHandler(coll.HandleInterpose, log),
		},

		Decider: hook.ObserveOnly{},
		Logger:  log,
		Budget:  cfg.LatencyBudget,
	})
	if err != nil {
		return err
	}

	ln, err := hook.Listen(cfg.HookAddr)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var otlpSrv *otlp.Server
	if cfg.OTLPEnabled {
		otlpSrv, err = otlp.NewServer(otlp.Options{
			Addr:   cfg.OTLPAddr,
			Sink:   coll.HandleOTel,
			Logger: log,
		})
		if err != nil {
			return err
		}
		otlpLn, err := otlp.Listen(cfg.OTLPAddr)
		if err != nil {
			return err
		}
		go func() {
			if serr := otlpSrv.Serve(ctx, otlpLn); serr != nil {
				log.Error("OTLP receiver stopped", "err", serr)
			}
		}()
	}

	log.Info("ambitd started",
		"version", version,
		"mode", "observe-only",
		"hook_addr", cfg.HookAddr,
		"otlp_addr", otlpAddrOrOff(cfg),
		"events", cfg.EventsPath,
		"trajectory", cfg.TrajectoryPath,
		"interpose_endpoint", cfg.HookAddr+interpose.Path,
		"baselines", cfg.BaselineDir,
	)

	runID, prev, rs := openRunState(cfg, log)
	hb := &heartbeat{
		cfg: cfg, coll: coll, srv: srv, events: events, traj: traj, otlpSrv: otlpSrv,
		version: version, log: log, start: time.Now(), runID: runID, prev: prev, rs: rs,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		hb.loop(ctx)
	}()

	err = srv.Serve(ctx, ln)
	stop()
	<-done
	hb.emit(true)

	st := coll.Stats()
	ot := coll.OTel()
	log.Info("ambitd stopped",
		"handled", st.Handled,
		"crossed", st.Crossed,
		"interesting_fraction", fmt.Sprintf("%.4f", coll.InterestingFraction()),
		"hook_tool_calls", ot.HookToolCalls,
		"otel_tool_calls", ot.ToolCalls,
		"stream_discrepant", ot.Discrepant,
		"interpose_reports", st.InterposeReports,
		"interpose_events", st.InterposeEvents,
		"prov_ingests", st.Provenance.Ingests,
		"prov_registered", st.Provenance.Registered,
		"prov_edge_events", st.Provenance.EdgeEvents,

		"prov_truncated", st.Provenance.Truncated,
		"prov_evicted", st.Provenance.Evicted,

		"shadow_deny", st.Shadow.Deny,
		"shadow_ask", st.Shadow.Ask,
		"shadow_allow_alert", st.Shadow.AllowAlert,
	)
	return err
}

func otlpAddrOrOff(cfg config.Config) string {
	if !cfg.OTLPEnabled {
		return "off"
	}
	return cfg.OTLPAddr
}

func openRunState(cfg config.Config, log *slog.Logger) (string, *event.PrevRun, *runstate.File) {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	runID := hex.EncodeToString(b)
	rs, prev, err := runstate.Open(runstate.PathFor(cfg.TrajectoryPath), runID, version, time.Now())
	if err != nil {
		log.Error("run state unavailable; restarts and downtime will not be reported", "err", err)
		rs = nil
	}
	if prev != nil {
		log.Info("previous run", "stop", prev.Stop, "run_id", prev.RunID, "down_sec", prev.DownSec)
	}
	return runID, prev, rs
}

type heartbeat struct {
	cfg     config.Config
	coll    *collector.Collector
	srv     *hook.Server
	events  *sink.Writer
	traj    *sink.Writer
	otlpSrv *otlp.Server
	version string
	log     *slog.Logger
	start   time.Time
	runID   string
	prev    *event.PrevRun
	rs      *runstate.File
}

func (h *heartbeat) loop(ctx context.Context) {
	ticker := time.NewTicker(h.cfg.HealthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.emit(false)
		}
	}
}

func (h *heartbeat) emit(final bool) {
	cfg, log := h.cfg, h.log
	st := h.coll.Stats()
	es, ts := h.events.Stats(), h.traj.Stats()
	hs := h.srv.Stats()

	status := "ok"

	if es.Dropped > 0 || ts.Dropped > 0 || es.WriteErrs > 0 || ts.WriteErrs > 0 || hs.ParseErrors > 0 || hs.QueueDropped > 0 {
		status = "degraded"
	}

	ot := h.coll.OTel()
	if cfg.OTLPEnabled && ot.Discrepant {
		status = "degraded"
	}
	if h.otlpSrv != nil {
		if rejected := h.otlpSrv.Stats().Rejected; rejected > 0 {

			status = "degraded"
			log.Error("OTLP exports are being rejected for wrong encoding",
				"rejected", rejected,
				"fix", "set OTEL_EXPORTER_OTLP_PROTOCOL=http/json")
		}
	}

	now := time.Now().UTC()
	lat := hs.Latency
	e := &event.Event{
		EventID:    fmt.Sprintf("health-%d", now.UnixNano()),
		TS:         now.Format(time.RFC3339Nano),
		IngestedAt: now.Format(time.RFC3339Nano),
		Source:     event.SourceAmbitd,
		SchemaV:    event.SchemaVersion,
		Kind:       event.KindAmbitdHealth,
		Endpoint: event.Endpoint{
			EndpointID:    cfg.EndpointID,
			AmbitdVersion: h.version,
		},
		Actor: event.Actor{UserID: cfg.UserID, OrgID: cfg.OrgID},
		Agent: event.Agent{Kind: "claude-code"},
		Health: &event.Health{
			Status:        status,
			QueueDepth:    es.QueueDepth + ts.QueueDepth,
			DroppedEvents: es.Dropped + ts.Dropped + hs.QueueDropped,
			UptimeSec:     int64(time.Since(h.start).Seconds()),

			RunID:   h.runID,
			Final:   final,
			Handled: st.Handled,
			Crossed: st.Crossed,
			Derived: st.Derived,

			ToolCalls:   st.HookToolCalls,
			ToolCrossed: st.HookToolCrossed,

			TrajectoryWritten: ts.Written,
			WriteErrors:       es.WriteErrs + ts.WriteErrs,
			ParseErrors:       hs.ParseErrors,
			TrajectoryRetired: ts.Retired,

			HookLatency: &lat,
			PrevRun:     h.prev,
		},
	}

	h.traj.Write(e)
	h.events.Write(event.Flatten(e))

	if h.rs != nil {
		var err error
		if final {
			err = h.rs.Stop(now)
		} else {
			err = h.rs.Beat(now)
		}
		if err != nil {
			log.Warn("run state not updated", "err", err)
		}
	}

	if status != "ok" {
		log.Warn("ambitd degraded",
			"events_dropped", es.Dropped, "trajectory_dropped", ts.Dropped,
			"events_write_errs", es.WriteErrs, "trajectory_write_errs", ts.WriteErrs,
			"hook_parse_errors", hs.ParseErrors)
	}
	log.Debug("health",
		"handled", st.Handled, "crossed", st.Crossed,
		"interesting_fraction", fmt.Sprintf("%.4f", h.coll.InterestingFraction()),
		"hook_tool_calls", ot.HookToolCalls, "otel_tool_calls", ot.ToolCalls,
		"stream_discrepant", ot.Discrepant,
		"hook_p99_us", lat.P99US, "hook_over_budget", lat.OverBudget)
}
