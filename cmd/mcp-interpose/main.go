package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/abijit2626/ambit/internal/baseline"
	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/interpose"
	"github.com/abijit2626/ambit/internal/labelsuggest"
)

var version = "0.0.0-dev"

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
		suggest     = flag.Bool("suggest-labels", false, "draft mcp_tool_labels for -server from its recorded tools and exit; review before use")
		showVersion = flag.Bool("version", false, "print version and exit")
		verbose     = flag.Bool("v", false, "verbose logging on stderr")
		upstream    = flag.String("url", "", "reach the server over HTTP at this URL instead of running a command")
		transport   = flag.String("transport", "http", "with -url: http (Streamable HTTP) or sse (the 2024-11-05 HTTP+SSE transport)")
		headers     headerFlags
	)
	flag.Var(headerValue{&headers, false}, "header", "with -url: a request header, as 'Name: value'; repeatable. Visible to anyone who can list processes")
	flag.Var(headerValue{&headers, true}, "header-env", "with -url: a request header whose value is read from an environment variable, as 'Name=VAR'; repeatable")
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

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return 1, err
	}
	dir := cfg.BaselineDir
	if *baselineDir != "" {
		dir = *baselineDir
	}

	if *approve || *revoke || *show || *suggest {
		if n := countTrue(*approve, *revoke, *show, *suggest); n > 1 {
			return 2, errors.New("-approve, -revoke, -show and -suggest-labels are separate actions; give one")
		}
		if *suggest {
			return suggestMode(dir, *serverName)
		}
		return adminMode(dir, *serverName, *approve, *revoke)
	}

	args := flag.Args()
	var bridge *interpose.Bridge
	if *upstream != "" {
		if len(args) > 0 {
			return 2, errors.New("-url and a server command are two ways to reach a server; give one")
		}
		b, err := newBridge(*upstream, *transport, headers)
		if err != nil {
			return 2, err
		}
		bridge = b
	} else {
		if len(headers) > 0 {
			return 2, errors.New("-header and -header-env apply only with -url")
		}
		if len(args) == 0 {
			return 2, errors.New("no server command given; put it after --, as in: -server github -- npx -y @modelcontextprotocol/server-github, or give -url for an HTTP server")
		}
	}

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		code    int
		pathErr error
	)
	if bridge != nil {
		code, pathErr = runBridge(ctx, bridge, analyzer, log, *serverName)
	} else {
		code, pathErr = runStdio(ctx, args, analyzer, log, *serverName, dir, client.URL())
	}

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

		log.Warn("interposer reports were not delivered to ambitd",
			"server", *serverName, "dropped", dropped+st.ReportsDropped, "endpoint", client.URL())
	}
	return code, pathErr
}

func runBridge(ctx context.Context, b *interpose.Bridge, analyzer *interpose.Analyzer, log *slog.Logger, server string) (int, error) {
	b.FromClient = os.Stdin
	b.ToClient = os.Stdout
	b.Analyzer = analyzer
	b.Logger = log
	log.Debug("interposing", "server", server, "host", b.URL.Host, "transport", b.Transport)
	err := b.Run(ctx)
	if err == nil || errors.Is(err, context.Canceled) {
		return 0, nil
	}
	return 1, err
}

func runStdio(ctx context.Context, args []string, analyzer *interpose.Analyzer, log *slog.Logger, server, dir, reportsTo string) (int, error) {
	cmd := exec.Command(args[0], args[1:]...)

	cmd.Stderr = os.Stderr
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("stdin pipe: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := killChildrenOnExit(); err != nil {
		log.Debug("could not tie the wrapped server's lifetime to ours", "err", err)
	}

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start %s: %w", args[0], err)
	}
	log.Debug("interposing",
		"server", server, "command", args[0], "pid", cmd.Process.Pid,
		"baselines", dir, "reports_to", reportsTo)

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

		CloseServerIn: func() { _ = serverIn.Close() },
		Analyzer:      analyzer,
		Logger:        log,
	}
	proxyErr := proxy.Run(ctx)

	waitErr := cmd.Wait()
	close(exited)

	if proxyErr != nil {
		log.Debug("relay ended with error", "err", proxyErr)
	}

	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if waitErr != nil {
		return 1, fmt.Errorf("wrapped server: %w", waitErr)
	}
	return 0, nil
}

func newBridge(raw, transport string, headers headerFlags) (*interpose.Bridge, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("-url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("-url: want an http or https URL with a host")
	}
	if u.User != nil {
		return nil, errors.New("-url: put credentials in -header-env, not in the URL, where they show in every log line and process listing")
	}
	t, err := interpose.ParseTransport(transport)
	if err != nil {
		return nil, fmt.Errorf("-transport: %w", err)
	}
	h, err := headers.resolve(os.Getenv)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "http" && len(h) > 0 && !isLoopbackHost(u.Hostname()) {
		fmt.Fprintf(os.Stderr, "mcp-interpose: warning: sending headers to %s over plain http\n", u.Host)
	}
	return &interpose.Bridge{URL: u, Transport: t, Header: h}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type headerFlag struct {
	raw     string
	fromEnv bool
}

type headerFlags []headerFlag

type headerValue struct {
	list    *headerFlags
	fromEnv bool
}

func (v headerValue) String() string { return "" }

func (v headerValue) Set(s string) error {
	*v.list = append(*v.list, headerFlag{raw: s, fromEnv: v.fromEnv})
	return nil
}

// resolve turns the flags into headers. A -header-env naming an unset or empty variable is an
// error rather than an empty header: the server would answer 401 to every request, and the
// developer would see a broken server with nothing saying why.
func (hs headerFlags) resolve(getenv func(string) string) (http.Header, error) {
	out := http.Header{}
	for _, h := range hs {
		sep := ":"
		if h.fromEnv {
			sep = "="
		}
		name, value, ok := strings.Cut(h.raw, sep)
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.ContainsAny(name, " \t\r\n:") {
			if h.fromEnv {
				return nil, fmt.Errorf("-header-env %q: want Name=VARIABLE", h.raw)
			}
			return nil, fmt.Errorf("-header %q: want 'Name: value'", h.raw)
		}
		value = strings.TrimSpace(value)
		if h.fromEnv {
			v := getenv(value)
			if v == "" {
				return nil, fmt.Errorf("-header-env %s: environment variable %s is unset or empty", name, value)
			}
			value = v
		}
		if strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("header %s: the value contains a line break", name)
		}
		out.Add(name, value)
	}
	return out, nil
}

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

func countTrue(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// suggestMode prints a mcp_tool_labels fragment on stdout and the reasoning on stderr, so the
// fragment can be redirected into a file while the review stays on screen.
func suggestMode(dir, server string) (int, error) {
	store, err := baseline.Open(dir)
	if err != nil {
		return 1, err
	}
	rec, err := store.Load(server)
	if err != nil {
		return 1, err
	}
	if len(rec.Tools) == 0 {
		return 1, fmt.Errorf("nothing recorded for server %q yet; run a session first (store: %s)", server, store.Dir())
	}
	suggestions := labelsuggest.For(rec)

	fmt.Fprintf(os.Stderr, "Draft labels for %q from %d recorded tools. Read this before using the fragment on stdout.\n\n", server, len(suggestions))
	named := 0
	for _, s := range suggestions {
		verdict := "default (untrusted input, acts)"
		if len(s.Labels) > 0 {
			verdict = strings.Join(s.Labels, ", ")
			named++
		}
		fmt.Fprintf(os.Stderr, "  %s -> %s\n", s.Tool, verdict)
		for _, r := range s.Reasons {
			fmt.Fprintf(os.Stderr, "      %s\n", r)
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d of %d tools get an entry; the rest keep the default and are not in the fragment.\n", named, len(suggestions))
	fmt.Fprintln(os.Stderr, "Every entry keeps \"untrusted\". read_only needs the name and the server's own hint to agree,")
	fmt.Fprintln(os.Stderr, "and a server can lie in both, so check each read_only against what the tool really does.")
	fmt.Fprintln(os.Stderr, "Merge the fragment into config.json by hand; this command never writes your config.")
	return 0, printJSON(labelsuggest.Fragment(server, suggestions))
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

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
