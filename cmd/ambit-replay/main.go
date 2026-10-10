package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/replay"
)

func main() { os.Exit(run()) }

func run() int {
	fs := flag.NewFlagSet("ambit-replay", flag.ContinueOnError)
	var (
		configPath   = fs.String("config", "", "collector config JSON (trusted domains, MCP servers, home); set home for reproducible path zones")
		asJSON       = fs.Bool("json", false, "write a machine-readable report to stdout")
		verbose      = fs.Bool("v", false, "list every step, not only failing ones")
		minConf      = fs.Float64("min-confidence", 0, "count an edge as a detection only at or above this confidence")
		minRecall    = fs.Float64("min-recall", -1, "fail if recall is below this (needs derived steps in the corpus)")
		minPrecision = fs.Float64("min-precision", -1, "fail if precision is below this")
		maxFPR       = fs.Float64("max-fpr", -1, "fail if the false-positive rate is above this")
		minRunRecall = fs.Float64("min-run-recall", -1, "fail if run-level recall is below this (needs runs labeled hostile)")
		maxRunFPR    = fs.Float64("max-run-fpr", -1, "fail if the run-level false-positive rate is above this")
	)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: ambit-replay [flags] <scenario.jsonl | directory>...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 1
	}

	cfg := replay.DefaultConfig()
	if *configPath != "" {

		if _, err := os.Stat(*configPath); err != nil {
			fmt.Fprintln(os.Stderr, "ambit-replay:", err)
			return 1
		}
		loaded, err := config.Load(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ambit-replay:", err)
			return 1
		}
		cfg = loaded
	}

	scenarios, err := replay.Load(fs.Args()...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ambit-replay:", err)
		return 1
	}

	results := make([]*replay.Result, 0, len(scenarios))
	for _, sc := range scenarios {
		results = append(results, replay.Run(sc, replay.Options{Config: cfg}))
	}
	sum := replay.Summarize(results, *minConf)

	var gate replay.Gate
	if *minRecall >= 0 {
		gate.MinRecall = minRecall
	}
	if *minPrecision >= 0 {
		gate.MinPrecision = minPrecision
	}
	if *maxFPR >= 0 {
		gate.MaxFPR = maxFPR
	}
	if *minRunRecall >= 0 {
		gate.MinRunRecall = minRunRecall
	}
	if *maxRunFPR >= 0 {
		gate.MaxRunFPR = maxRunFPR
	}
	violations := gate.Check(sum)

	if *asJSON {
		if err := replay.WriteJSON(os.Stdout, results, sum); err != nil {
			fmt.Fprintln(os.Stderr, "ambit-replay:", err)
			return 1
		}
	} else {
		replay.WriteText(os.Stdout, results, sum, *verbose)
	}

	if len(violations) > 0 {

		fmt.Fprintln(os.Stderr)
		for _, v := range violations {
			fmt.Fprintln(os.Stderr, "ambit-replay: FAIL:", v)
		}
		return 2
	}
	return 0
}
