// Package stopctl lets ambitd be stopped cleanly where the OS has no gentle way to ask. On Windows,
// Stop-ScheduledTask and Stop-Process terminate the process outright, so ambitd never writes its
// final heartbeat and the next run reports the stop as unclean. `ambitd stop` asks instead: it reads
// a token ambitd wrote at startup into its private data directory and posts it to /shutdown, which
// cancels the run the same way SIGTERM does.
//
// The token is the whole of the authorization. Whoever can read it can already read ambitd's data
// directory, which on a system install is root or SYSTEM and Administrators only: the same people
// who could kill the process. The endpoint adds a polite way to stop ambitd, not a new one.
package stopctl

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/fsperm"
)

const (
	Path     = "/shutdown"
	Header   = "X-Ambit-Stop-Token"
	FileName = "stop.token"
)

// TokenPath puts the token beside the spool, in the directory ambitd already keeps private.
func TokenPath(trajectoryPath string) string {
	return filepath.Join(filepath.Dir(trajectoryPath), FileName)
}

// WriteToken makes a fresh token for this run. A token from an earlier run is overwritten, so it stops
// working when the process that wrote it is gone.
func WriteToken(path string) (string, error) {
	if err := fsperm.PrivateDir(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("stop token dir: %w", err)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tok, nil
}

func readToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return tok, nil
}

// Handler cancels the run when it receives a POST carrying the token. A request with an Origin header
// is refused whatever it carries: only a browser sends one, and nothing legitimate stops ambitd from a
// web page.
func Handler(token string, stop func()) http.Handler {
	var once sync.Once
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Origin") != "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		got := []byte(r.Header.Get(Header))
		if len(want) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "stopping\n")
		once.Do(stop)
	})
}

// Main is `ambitd stop`: ask the running ambitd to stop, then wait until its hook endpoint stops
// answering. Exit 0 when it stopped or was not running, 1 when it could not be asked or did not stop.
func Main(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "ambitd config JSON (defaults apply when absent)")
	timeout := fs.Duration("timeout", 15*time.Second, "how long to wait for ambitd to stop")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "ambitd stop:", err)
		return 1
	}
	base := "http://" + cfg.HookAddr
	client := &http.Client{Timeout: 2 * time.Second}

	if !answers(client, base) {
		fmt.Fprintln(stdout, "ambitd is not running on", cfg.HookAddr)
		return 0
	}
	tok, err := readToken(TokenPath(cfg.TrajectoryPath))
	if err != nil {
		fmt.Fprintln(stderr, "ambitd stop: no stop token (an ambitd older than `ambitd stop`, or a different data directory):", err)
		return 1
	}
	if err := ask(client, base, tok); err != nil {
		fmt.Fprintln(stderr, "ambitd stop:", err)
		return 1
	}
	deadline := time.Now().Add(*timeout)
	for time.Now().Before(deadline) {
		if !answers(client, base) {
			fmt.Fprintln(stdout, "ambitd stopped")
			return 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintf(stderr, "ambitd stop: still answering on %s after %s\n", cfg.HookAddr, *timeout)
	return 1
}

func answers(c *http.Client, base string) bool {
	resp, err := c.Get(base + "/healthz")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func ask(c *http.Client, base, tok string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+Path, nil)
	if err != nil {
		return err
	}
	req.Header.Set(Header, tok)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusAccepted:
		return nil
	case http.StatusNotFound:
		return errors.New("this ambitd has no " + Path + " endpoint; it predates `ambitd stop`")
	default:
		return fmt.Errorf("%s answered %s; is the token from this run?", Path, resp.Status)
	}
}
