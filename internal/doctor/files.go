package doctor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/abijit2626/ambit/internal/config"
)

// minKeyBytes is the shortest fingerprint key ambitd accepts at start (config.LoadOrCreateFingerprintKey).
const minKeyBytes = 32

type privatePath struct {
	what, path string
	dir        bool
}

// filesFinding checks that ambitd's own files are as private as ambitd made them: every file 0600 and
// every directory 0700. The key is what keys every digest that leaves the endpoint, the spool holds the
// session record, and the profile and baselines decide what counts as new; group or world access to
// any of them is a leak or a way to tamper. Windows is not checked here: ambitd sets an explicit ACL
// when it creates them (internal/fsperm), and a mode says nothing about one.
func filesFinding(cfg config.Config) []Finding {
	if runtime.GOOS == "windows" {
		return []Finding{{Level: OK, Check: "files", Detail: "not checked on Windows, where ambitd sets an explicit ACL on its directories when it creates them"}}
	}
	paths := []privatePath{
		{"fingerprint key", cfg.FingerprintKeyPath, false},
		{"spool", cfg.TrajectoryPath, false},
		{"events sink", cfg.EventsPath, false},
		{"egress profile", cfg.EgressProfile(), false},
		{"data directory", filepath.Dir(cfg.TrajectoryPath), true},
		{"baseline directory", cfg.BaselineDir, true},
	}
	var out []Finding
	var unreadable []string
	checked := 0
	for _, p := range paths {
		if p.path == "" {
			continue
		}
		info, err := os.Stat(p.path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			unreadable = append(unreadable, p.what)
			continue
		}
		checked++
		if open := info.Mode().Perm() & 0o077; open != 0 {
			out = append(out, Finding{Level: Fail, Check: "files", Detail: fmt.Sprintf(
				"the %s %s is %s, open to %s; ambitd creates it %s", p.what, p.path, info.Mode().Perm(), who(open), want(p.dir))})
		}
		if p.what == "fingerprint key" && !p.dir && info.Size() < minKeyBytes {
			out = append(out, Finding{Level: Fail, Check: "files", Detail: fmt.Sprintf(
				"the fingerprint key %s is %d bytes; ambitd refuses to start with fewer than %d", p.path, info.Size(), minKeyBytes)})
		}
	}
	if len(unreadable) > 0 {
		out = append(out, Finding{Level: Warn, Check: "files", Detail: fmt.Sprintf(
			"cannot inspect the %s; run doctor as the account ambitd runs as to check them", strings.Join(unreadable, ", "))})
	}
	if len(out) == 0 {
		out = append(out, Finding{Level: OK, Check: "files", Detail: fmt.Sprintf("%d of ambitd's files and directories are private to their owner", checked)})
	}
	return out
}

func who(bits fs.FileMode) string {
	var w []string
	if bits&0o070 != 0 {
		w = append(w, "its group")
	}
	if bits&0o007 != 0 {
		w = append(w, "everyone")
	}
	return strings.Join(w, " and ")
}

func want(dir bool) string {
	if dir {
		return "0700"
	}
	return "0600"
}
