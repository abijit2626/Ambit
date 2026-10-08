// Command agentdojo-convert turns AgentDojo run logs into ambit replay trajectories.
//
//	agentdojo-convert -out converted/ path/to/agentdojo/runs/<model>
//	ambit-replay converted/
//
// It walks each path for *.json run logs, writes one .jsonl trajectory per run into -out
// (flat, so ambit-replay can read the directory), and prints what it converted by outcome.
// See internal/agentdojo for the mapping and, more importantly, the ground truth it does
// and does not claim.
//
// Exit status: 0 on success, 1 on any error. An unreadable or malformed run log is an
// error, not a skip: a converter that quietly drops the files it cannot parse reports a
// measurement over a corpus nobody chose.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/abijit2626/ambit/internal/agentdojo"
)

func main() { os.Exit(run()) }

func run() int {
	fl := flag.NewFlagSet("agentdojo-convert", flag.ContinueOnError)
	out := fl.String("out", "", "directory to write trajectories into; must be empty or absent")
	fl.Usage = func() {
		fmt.Fprintln(fl.Output(), "usage: agentdojo-convert -out <dir> <runs-dir | run.json>...")
		fl.PrintDefaults()
	}
	if err := fl.Parse(os.Args[1:]); err != nil {
		return 1
	}
	if *out == "" || fl.NArg() == 0 {
		fl.Usage()
		return 1
	}
	if err := convert(*out, fl.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "agentdojo-convert:", err)
		return 1
	}
	return 0
}

func convert(outDir string, paths []string) error {
	// Refuse a directory that already holds trajectories. Mixing a previous conversion's
	// files with this one's would replay a corpus that is neither, and nothing downstream
	// could tell.
	if ents, err := os.ReadDir(outDir); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".jsonl") {
				return fmt.Errorf("%s already holds trajectories (%s); use an empty directory", outDir, e.Name())
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	var files []string
	for _, p := range paths {
		err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".json") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("no *.json run logs under %s", strings.Join(paths, ", "))
	}
	sort.Strings(files)

	counts := map[agentdojo.Outcome]int{}
	seen := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		r, err := agentdojo.Parse(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		body, outcome, err := agentdojo.Convert(r)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		name := r.Name()
		if prev, dup := seen[name]; dup {
			return fmt.Errorf("%s and %s convert to the same scenario %q", prev, f, name)
		}
		seen[name] = f
		if err := os.WriteFile(filepath.Join(outDir, name+".jsonl"), body, 0o644); err != nil {
			return err
		}
		counts[outcome]++
	}

	fmt.Fprintf(os.Stderr, "agentdojo-convert: %d runs -> %s\n", len(files), outDir)
	for _, o := range []agentdojo.Outcome{
		agentdojo.OutcomeAttackSucceeded, agentdojo.OutcomeAttackFailed, agentdojo.OutcomeNoAttack,
		agentdojo.OutcomeUserGoal, agentdojo.OutcomeErrored, agentdojo.OutcomeDoS, agentdojo.OutcomeUnscored,
	} {
		if n := counts[o]; n > 0 {
			label := "unlabeled"
			if h := o.Hostile(); h != nil && *h {
				label = "hostile"
			} else if h != nil {
				label = "benign"
			}
			fmt.Fprintf(os.Stderr, "  %-20s %5d  (%s)\n", o, n, label)
		}
	}
	return nil
}
