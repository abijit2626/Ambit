// Package hookfwd is `ambitd hook-forward`: a command hook that hands one hook payload to the
// running ambitd.
//
// Claude Code does not deliver SessionStart to a hook of type http, only to command (and
// mcp_tool) hooks, so the managed settings register SessionStart as a command that runs this.
// The payload arrives on stdin, exactly as an http hook would receive it in a request body, and
// is posted unchanged to ambitd's /hook endpoint.
//
// Three properties are the point of the package and are tested:
//
//   - It prints nothing to stdout. For SessionStart, whatever a hook prints on stdout is added
//     to the model's context, so a forwarder that said anything would change the conversation.
//   - It always exits 0. A monitoring failure must not block or alter the user's session. A
//     failure costs one line on stderr instead of silence, so a broken forwarder can be found.
//   - It only talks to a loopback address, so a mistyped -addr cannot send session metadata
//     to another host.
package hookfwd

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/loopback"
)

const (
	DefaultTimeout = 2 * time.Second

	// MaxBody matches the limit ambitd's /hook handler applies when it reads a request.
	MaxBody = 4 << 20
)

// readTimeout bounds how long Main waits for the hook runner to finish writing stdin.
var readTimeout = 3 * time.Second

// Main runs the subcommand with the arguments after "hook-forward". It returns the exit code,
// which is always 0.
func Main(args []string, stdin io.Reader, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "ambitd hook-forward: "+format+"\n", a...)
		return 0
	}

	fs := flag.NewFlagSet("hook-forward", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", "", "ambitd hook address; default is hook_addr from -config, or 127.0.0.1:7777")
	cfgPath := fs.String("config", "", "ambitd config JSON to read hook_addr from")
	timeout := fs.Duration("timeout", DefaultTimeout, "how long to wait for ambitd")
	if err := fs.Parse(args); err != nil {
		return fail("bad arguments: %v", err)
	}

	target := *addr
	if target == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return fail("cannot read the config for hook_addr: %v", err)
		}
		target = cfg.HookAddr
	}
	if err := loopback.Validate(target); err != nil {
		return fail("refusing to send anything: %v", err)
	}

	body, err := readAll(stdin)
	if err != nil {
		return fail("%v", err)
	}
	if len(body) == 0 {
		return fail("no payload on stdin; nothing sent")
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+target+"/hook", bytes.NewReader(body))
	if err != nil {
		return fail("%v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout:   *timeout,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail("ambitd did not take the payload: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fail("ambitd answered %s", resp.Status)
	}
	return 0
}

// readAll reads stdin up to MaxBody within readTimeout. A payload cut off at the limit is an
// error rather than a truncated send: half a JSON object would be dropped by ambitd anyway.
func readAll(r io.Reader) ([]byte, error) {
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(r, MaxBody+1))
		done <- result{b, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			return nil, fmt.Errorf("reading stdin: %w", res.err)
		}
		if len(res.b) > MaxBody {
			return nil, fmt.Errorf("payload is larger than %d bytes; nothing sent", MaxBody)
		}
		return res.b, nil
	case <-time.After(readTimeout):
		return nil, fmt.Errorf("stdin was not closed within %s; nothing sent", readTimeout)
	}
}
