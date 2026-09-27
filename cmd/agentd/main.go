// Command agentd is the endpoint half of the indirect-prompt control plane.
//
// In M0 it is observe-only: it receives Claude Code hook events, normalizes them,
// writes the full trajectory to a local spool and the filtered security-relevant
// slice to a file the Wazuh agent tails. It returns no decision to Claude Code,
// so no session behaves differently for its presence. That is the milestone's
// whole point — a baseline cannot be measured from a system that is already
// changing behavior. See docs/05-build-plan.md.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abijit2626/indirect-prompt/internal/collector"
	"github.com/abijit2626/indirect-prompt/internal/config"
	"github.com/abijit2626/indirect-prompt/internal/event"
	"github.com/abijit2626/indirect-prompt/internal/features"
	"github.com/abijit2626/indirect-prompt/internal/hook"
	"github.com/abijit2626/indirect-prompt/internal/sink"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agentd:", err)
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

	// Refuse to start in enforce mode: no policy engine exists yet, and a config
	// that asks for enforcement should fail loudly rather than be silently
	// ignored. Someone who sets this believes the gate is on.
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
		// ObserveOnly is explicit rather than defaulted: the inert response is
		// the milestone guarantee and should be visible at the call site.
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

	log.Info("agentd started",
		"version", version,
		"mode", "observe-only",
		"hook_addr", cfg.HookAddr,
		"events", cfg.EventsPath,
		"trajectory", cfg.TrajectoryPath,
	)

	go emitHealth(ctx, cfg, coll, events, traj, version, log)

	err = srv.Serve(ctx, ln)

	st := coll.Stats()
	log.Info("agentd stopped",
		"handled", st.Handled,
		"crossed", st.Crossed,
		"interesting_fraction", fmt.Sprintf("%.4f", coll.InterestingFraction()),
	)
	return err
}

// emitHealth writes a periodic agentd_health event.
//
// This is the fine half of D7. Wazuh's rule 504 catches the endpoint going dark,
// and SCA's p:agentd check catches the process being gone, but neither can tell a
// wedged daemon from a healthy one. A stale heartbeat with the process present is
// what distinguishes them. See docs/03-detection.md.
func emitHealth(
	ctx context.Context,
	cfg config.Config,
	coll *collector.Collector,
	events *sink.Writer,
	traj *sink.Writer,
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
			// Any drop or write error is degraded, not ok. A monitor that reports
			// "ok" while losing events is worse than no monitor.
			if es.Dropped > 0 || ts.Dropped > 0 || es.WriteErrs > 0 || ts.WriteErrs > 0 {
				status = "degraded"
			}

			now := time.Now().UTC()
			e := &event.Event{
				EventID:    fmt.Sprintf("health-%d", now.UnixNano()),
				TS:         now.Format(time.RFC3339Nano),
				IngestedAt: now.Format(time.RFC3339Nano),
				Source:     event.SourceAgentd,
				SchemaV:    event.SchemaVersion,
				Kind:       event.KindAgentdHealth,
				Endpoint: event.Endpoint{
					EndpointID:    cfg.EndpointID,
					AgentdVersion: version,
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
			// Health goes to both sinks: Wazuh needs it for D7 and D11, and the
			// spool needs it to explain gaps during an investigation.
			traj.Write(e)
			events.Write(event.Flatten(e))

			if status != "ok" {
				log.Warn("agentd degraded",
					"events_dropped", es.Dropped, "trajectory_dropped", ts.Dropped,
					"events_write_errs", es.WriteErrs, "trajectory_write_errs", ts.WriteErrs)
			}
			log.Debug("health",
				"handled", st.Handled, "crossed", st.Crossed,
				"interesting_fraction", fmt.Sprintf("%.4f", coll.InterestingFraction()))
		}
	}
}
