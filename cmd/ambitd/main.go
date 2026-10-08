package main

import (
	"context"
	"crypto/rand"
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
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/features"
	"github.com/abijit2626/ambit/internal/hook"
	"github.com/abijit2626/ambit/internal/interpose"
	"github.com/abijit2626/ambit/internal/otlp"
	"github.com/abijit2626/ambit/internal/sink"
)

var version = "0.0.0-dev"

func main() {
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

	go emitHealth(ctx, cfg, coll, events, traj, otlpSrv, version, log)

	err = srv.Serve(ctx, ln)

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

func emitHealth(
	ctx context.Context,
	cfg config.Config,
	coll *collector.Collector,
	events *sink.Writer,
	traj *sink.Writer,
	otlpSrv *otlp.Server,
	version string,
	log *slog.Logger,
) {
	start := time.Now()
	ticker := time.NewTicker(cfg.HealthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st := coll.Stats()
			es, ts := events.Stats(), traj.Stats()

			status := "ok"

			if es.Dropped > 0 || ts.Dropped > 0 || es.WriteErrs > 0 || ts.WriteErrs > 0 {
				status = "degraded"
			}

			ot := coll.OTel()
			if cfg.OTLPEnabled && ot.Discrepant {
				status = "degraded"
			}
			if otlpSrv != nil {
				if rejected := otlpSrv.Stats().Rejected; rejected > 0 {

					status = "degraded"
					log.Error("OTLP exports are being rejected for wrong encoding",
						"rejected", rejected,
						"fix", "set OTEL_EXPORTER_OTLP_PROTOCOL=http/json")
				}
			}

			now := time.Now().UTC()
			e := &event.Event{
				EventID:    fmt.Sprintf("health-%d", now.UnixNano()),
				TS:         now.Format(time.RFC3339Nano),
				IngestedAt: now.Format(time.RFC3339Nano),
				Source:     event.SourceAmbitd,
				SchemaV:    event.SchemaVersion,
				Kind:       event.KindAmbitdHealth,
				Endpoint: event.Endpoint{
					EndpointID:    cfg.EndpointID,
					AmbitdVersion: version,
				},
				Actor: event.Actor{UserID: cfg.UserID, OrgID: cfg.OrgID},
				Agent: event.Agent{Kind: "claude-code"},
				Health: &event.Health{
					Status:        status,
					QueueDepth:    es.QueueDepth + ts.QueueDepth,
					DroppedEvents: es.Dropped + ts.Dropped,
					UptimeSec:     int64(time.Since(start).Seconds()),
				},
			}

			traj.Write(e)
			events.Write(event.Flatten(e))

			if status != "ok" {
				log.Warn("ambitd degraded",
					"events_dropped", es.Dropped, "trajectory_dropped", ts.Dropped,
					"events_write_errs", es.WriteErrs, "trajectory_write_errs", ts.WriteErrs)
			}
			log.Debug("health",
				"handled", st.Handled, "crossed", st.Crossed,
				"interesting_fraction", fmt.Sprintf("%.4f", coll.InterestingFraction()),
				"hook_tool_calls", ot.HookToolCalls, "otel_tool_calls", ot.ToolCalls,
				"stream_discrepant", ot.Discrepant)
		}
	}
}
