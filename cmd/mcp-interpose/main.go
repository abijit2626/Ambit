// Command mcp-interpose wraps one MCP server and reports what it advertises.
//
// It is configured as the server command in .mcp.json, in front of the real
// server, one interposer per server:
//
//	{
//	  "mcpServers": {
//	    "github": {
//	      "command": "mcp-interpose",
//	      "args": ["-server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
//	    }
//	  }
//	}
//
// Per server, not in front of all of them, is the load-bearing choice. Claude Code
// still sees one MCP server per real server under its real name, so tool identity
// stays mcp__<server>__<tool>: per-tool permission rules in managed settings keep
// working, hook matchers keep working, and ambitd's own parsing keeps working. The
// aggregating gateways evaluated in docs/05-mcp-interpose-decision.md all broke
// that, which is most of why this exists.
//
// What it does: hashes each tool's name, description and input schema and compares
// against an approved baseline (D4), scans advertised text for instruction-shaped
// language and cross-server references (D5), and carries MCP annotations into the
// event stream as inputs to policy that may only make it stricter. What it does
// not do: decide anything. Every frame is forwarded before it is parsed, no
// response is ever altered, and there is no path by which a finding can block a
// tool call. Enforcement starts at M3 (see the Roadmap in README.md).
//
// Operator workflow:
//
//	mcp-interpose -server github -show      # what has been recorded
//	mcp-interpose -server github -approve   # approve the current surface
//	mcp-interpose -server github -revoke    # withdraw approval after an incident
//
// stdout carries MCP protocol and nothing else. Every diagnostic goes to stderr,
// which is where the MCP stdio transport expects a server's logs; a stray line on
// stdout presents as a mysteriously broken server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/abijit2626/ambit/internal/baseline"
	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/interpose"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

// shutdownGrace bounds report delivery at exit. The interposer sits on the path of
// the agent's own shutdown, so a wedged ambitd costs a bounded delay and a counted
// undelivered report, never a hung session.
const shutdownGrace = 3 * time.Second

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp-interpose:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func run() (int, error) {
	var (
		serverName  = flag.String("server", "", "logical MCP server name; must match the key in .mcp.json")
		configPath  = flag.String("config", "", "path to ambit config JSON (defaults apply when absent)")
		baselineDir = flag.String("baseline-dir", "", "override the baseline store directory")
		siblings    = flag.String("siblings", "", "comma-separated names of other MCP servers, for D5's cross-server rule")
		sessionID   = flag.String("session-id", "", "Claude Code session id, if the caller knows it")
		approve     = flag.Bool("approve", false, "approve the recorded surface for -server and exit")
		revoke      = flag.Bool("revoke", false, "withdraw approval for -server and exit")
		show        = flag.Bool("show", false, "print the recorded baseline for -server and exit")
		showVersion = flag.Bool("version", false, "print version and exit")
		verbose     = flag.Bool("v", false, "verbose logging on stderr")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return 0, nil
	}
	if *serverName == "" {
		return 2, errors.New("-server is required; it must match the server's key in .mcp.json")
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	// stderr, always. stdout belongs to the protocol.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return 1, err
	}
	dir := cfg.BaselineDir
	if *baselineDir != "" {
		dir = *baselineDir
	}

	if *approve || *revoke || *show {
		return adminMode(dir, *serverName, *approve, *revoke)
	}

	args := flag.Args()
	if len(args) == 0 {
		return 2, errors.New("no server command given; put it after --, as in: -server github -- npx -y @modelcontextprotocol/server-github")
	}

	// A store that cannot be opened is a degraded mode, not a failure: D5 still
	// works without it, and refusing to start would take the developer's MCP
	// server down with us. Every report then says the baseline was unavailable, so
	// "no drift" is never reported when the truth is "nothing was compared".
	var (
		store    *baseline.Store
		storeErr error
	)
	store, storeErr = baseline.Open(dir)
	if storeErr != nil {
		store = nil
		log.Error("baseline store unavailable; D4 disabled for this session, D5 continues",
			"dir", dir, "err", storeErr)
	}

	client := interpose.NewClient(cfg.HookAddr)
	analyzer := interpose.NewAnalyzer(interpose.Options{
		Server:    *serverName,
		Siblings:  siblingNames(*siblings, cfg, *serverName),
		Store:     store,
		StoreErr:  storeErr,
		Sender:    client,
		Logger:    log,
		Version:   version,
		SessionID: resolveSessionID(*sessionID),
	})

	cmd := exec.Command(args[0], args[1:]...)
	// The wrapped server's stderr passes through untouched: it is the developer's
	// own diagnostic channel and swallowing it would make debugging a wrapped
	// server worse than debugging an unwrapped one.
	cmd.Stderr = os.Stderr
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("stdin pipe: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("stdout pipe: %w", err)
	}

	// On Windows, put this process in a job object that kills whatever is still in it
	// when we go. The wrapped server is often `npx` or a .cmd shim with the real server
	// as a grandchild, and an MCP host stops a stdio server with TerminateProcess,
	// which runs none of our code: without this the grandchildren outlive us.
	if err := killChildrenOnExit(); err != nil {
		log.Debug("could not tie the wrapped server's lifetime to ours", "err", err)
	}

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start %s: %w", args[0], err)
	}
	log.Debug("interposing",
		"server", *serverName, "command", args[0], "pid", cmd.Process.Pid,
		"baselines", dir, "reports_to", client.URL())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Forward a signal to the wrapped server rather than dying and orphaning it.
	//
	// ctx is also cancelled by the deferred stop() when run returns, which is after
	// the server has exited and been reaped. By then the process is gone, and on
	// Windows terminate works by PID, which the system may have given to an unrelated
	// process. exited is closed as soon as Wait returns, and a cancellation that
	// arrives after it is not a signal.
	exited := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-exited:
			return
		}
		select {
		case <-exited:
			return
		default:
		}
		terminate(cmd.Process)
	}()

	proxy := &interpose.Proxy{
		FromClient: os.Stdin,
		ToServer:   serverIn,
		FromServer: serverOut,
		ToClient:   os.Stdout,
		// Closing the server's stdin on client EOF is what lets the wrapped
		// process exit on its own terms instead of being killed.
		CloseServerIn: func() { _ = serverIn.Close() },
		Analyzer:      analyzer,
		Logger:        log,
	}
	proxyErr := proxy.Run(ctx)

	waitErr := cmd.Wait()
	close(exited)

	closeCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	analyzer.Close(closeCtx)
	cancel()

	st := analyzer.Stats()
	sent, dropped := client.Stats()
	log.Debug("interposer stopped",
		"server", *serverName, "listings", st.Listings, "calls", st.Calls,
		"frames_dropped", st.FramesDropped, "frames_unparsed", st.FramesUnparsed,
		"reports_sent", sent, "reports_dropped", dropped+st.ReportsDropped)
	if dropped+st.ReportsDropped > 0 {
		// Loud, because an interposer whose reports never arrive looks exactly like
		// a server with nothing to report.
		log.Warn("interposer reports were not delivered to ambitd",
			"server", *serverName, "dropped", dropped+st.ReportsDropped, "endpoint", client.URL())
	}
	if proxyErr != nil {
		log.Debug("relay ended with error", "err", proxyErr)
	}

	// The wrapped server's exit status is ours: the client is entitled to see the
	// same outcome it would have seen without us in the path.
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if waitErr != nil {
		return 1, fmt.Errorf("wrapped server: %w", waitErr)
	}
	return 0, nil
}

// adminMode implements -show, -approve and -revoke: the explicit operator step
// that turns an inventory into a control.
func adminMode(dir, server string, approve, revoke bool) (int, error) {
	store, err := baseline.Open(dir)
	if err != nil {
		return 1, err
	}
	switch {
	case approve:
		rec, err := store.Approve(server, currentUser(), time.Now())
		if err != nil {
			return 1, err
		}
		// Printed, not silent: approval takes whatever the server is advertising
		// right now, so the operator should see what they just blessed.
		fmt.Fprintf(os.Stderr, "approved %d tools for server %q\n", len(rec.Tools), server)
		return 0, printJSON(rec)
	case revoke:
		rec, err := store.Revoke(server)
		if err != nil {
			return 1, err
		}
		fmt.Fprintf(os.Stderr, "approval withdrawn for server %q; listings now report against a provisional baseline\n", server)
		return 0, printJSON(rec)
	default:
		rec, err := store.Load(server)
		if err != nil {
			return 1, err
		}
		if len(rec.Tools) == 0 {
			fmt.Fprintf(os.Stderr, "nothing recorded for server %q yet; run a session first (store: %s)\n", server, store.Dir())
		}
		return 0, printJSON(rec)
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// siblingNames assembles the other-server list for D5's cross-server rule.
//
// The flag wins when given. Otherwise the trusted-server list from configuration
// is used, which is an approximation: it is the only list of sibling names ambit
// currently holds. Cross-server detection does not depend on it — the
// mcp__<server>__<tool> form needs no configuration — so an incomplete list costs
// one rule's coverage rather than the detector.
func siblingNames(flagValue string, cfg config.Config, self string) []string {
	raw := cfg.TrustedMCPServers
	if strings.TrimSpace(flagValue) != "" {
		raw = strings.Split(flagValue, ",")
	}
	out := make([]string, 0, len(raw))
	for _, name := range raw {
		name = strings.TrimSpace(name)
		if name != "" && !strings.EqualFold(name, self) {
			out = append(out, name)
		}
	}
	return out
}

// sessionEnvVars are checked for a session id, in order.
//
// This is best-effort by necessity: the MCP protocol carries no Claude Code
// session id, and nothing documented guarantees one reaches a server's
// environment. An id is used when the runtime or the operator provides one and is
// left empty otherwise — an event correlated to the wrong session would be worse
// than one correlated to none.
var sessionEnvVars = []string{"AMBIT_SESSION_ID", "CLAUDE_SESSION_ID"}

func resolveSessionID(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	for _, key := range sessionEnvVars {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return os.Getenv("USERNAME")
}
