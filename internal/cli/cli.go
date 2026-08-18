// Package cli implements the harbinger subcommands. Kept separate from main so
// it is unit-testable.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/analyze"
	"github.com/harbingerlabs/harbinger-cli/internal/diff"
	"github.com/harbingerlabs/harbinger-cli/internal/features"
	"github.com/harbingerlabs/harbinger-cli/internal/load"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/pathfind"
	"github.com/harbingerlabs/harbinger-cli/internal/report"
	"github.com/harbingerlabs/harbinger-cli/internal/score"
	"github.com/harbingerlabs/harbinger-cli/internal/synth"
)

// SchemaVersion exposes the outbound feature schema version.
func SchemaVersion() string { return features.SchemaVersion }

// commonFlags are shared by analyze/diff.
type commonFlags struct {
	offline     bool
	apiKey      string
	apiURL      string
	hvt         string
	domain      string
	jsonOut     bool
	reportPath  string
	top         int
	quiet       bool
	verbose     bool
	noColor     bool
	showPayload bool
	maxHops     int
	kPaths      int
	maxStarts   int
}

func (c *commonFlags) bind(fs *flag.FlagSet) {
	fs.BoolVar(&c.offline, "offline", false, "score fully locally; make ZERO network calls (default when no --api-key)")
	fs.StringVar(&c.apiKey, "api-key", "", "Harbinger API key -> opt in to hybrid scoring (or env HARBINGER_API_KEY)")
	fs.StringVar(&c.apiURL, "api-url", "", "override scoring server base URL (or env HARBINGER_API_URL)")
	fs.StringVar(&c.hvt, "hvt", "", "extra High-Value Targets (comma-separated SIDs or names)")
	fs.StringVar(&c.domain, "domain", "", "restrict the analysis to one directory (DNS name or domain SID)")
	fs.BoolVar(&c.jsonOut, "json", false, "emit full structured JSON to stdout")
	fs.StringVar(&c.reportPath, "report", "", "write a shareable report to this file (.html or .md)")
	fs.IntVar(&c.top, "top", 10, "number of paths to show")
	fs.BoolVar(&c.quiet, "quiet", false, "suppress load diagnostics / progress")
	fs.BoolVar(&c.verbose, "verbose", false, "print load counts and warnings")
	fs.BoolVar(&c.noColor, "no-color", false, "disable ANSI color")
	fs.BoolVar(&c.showPayload, "show-payload", false, "print the exact tokenized payload that would be transmitted, then continue")
	fs.IntVar(&c.maxHops, "max-hops", 12, "maximum attack-path length")
	fs.IntVar(&c.kPaths, "k-paths", 15, "k-shortest paths to enumerate to the crown")
	fs.IntVar(&c.maxStarts, "max-starts", 0, "cap number of low-priv start principals (0 = all; use to bound very large graphs)")
}

func (c *commonFlags) resolve() {
	if c.apiKey == "" {
		c.apiKey = os.Getenv("HARBINGER_API_KEY")
	}
	if c.apiURL == "" {
		c.apiURL = os.Getenv("HARBINGER_API_URL")
	}
	// Privacy-first: offline is the default unless the user explicitly opts into
	// hybrid by supplying a key AND not forcing --offline.
	if c.apiKey == "" {
		c.offline = true
	}
}

func (c *commonFlags) scorer(version string) score.Scorer {
	if c.offline {
		return score.Distilled{}
	}
	return score.NewAPI(c.apiURL, c.apiKey, version)
}

func (c *commonFlags) options() pathfind.Options {
	return pathfind.Options{MaxHops: c.maxHops, KPerCrown: c.kPaths, MaxStarts: c.maxStarts}
}

func (c *commonFlags) palette() report.Palette {
	return report.Palette{Color: !c.noColor && !c.quiet && isTerminal(os.Stdout) && colorSupported(os.LookupEnv)}
}

// CmdAnalyze runs single-snapshot analysis.
func CmdAnalyze(args []string, version string) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var cf commonFlags
	cf.bind(fs)
	fs.Usage = func() { analyzeUsage(os.Stderr) }
	pos, err := parseArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) < 1 {
		fmt.Fprint(os.Stderr, "error: analyze needs an export path\n\n")
		analyzeUsage(os.Stderr)
		return 2
	}
	cf.resolve()

	g, loadRep, err := load.Any(pos[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if cf.verbose {
		printLoad(os.Stderr, loadRep)
	}

	sc := cf.scorer(version)
	res, req, err := analyze.Run(context.Background(), g, loadRep, splitCSV(cf.hvt), cf.domain, cf.options(), sc, version)
	if cf.showPayload {
		showPayload(os.Stderr, req, sc.Transmits())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scoring failed: %v\n", err)
		return 1
	}

	return emit(res, nil, &cf)
}

// CmdDiff runs a t0 -> t1 comparison.
func CmdDiff(args []string, version string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var cf commonFlags
	cf.bind(fs)
	fs.Usage = func() { diffUsage(os.Stderr) }
	pos, err := parseArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) < 2 {
		fmt.Fprint(os.Stderr, "error: diff needs two export paths: <t0> <t1>\n\n")
		diffUsage(os.Stderr)
		return 2
	}
	cf.resolve()

	g0, load0, err := load.Any(pos[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: t0: %v\n", err)
		return 1
	}
	g1, load1, err := load.Any(pos[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: t1: %v\n", err)
		return 1
	}
	if cf.verbose {
		printLoad(os.Stderr, load1)
	}

	sc := cf.scorer(version)
	d, err := diff.Compare(context.Background(), g0, g1, load0, load1, splitCSV(cf.hvt), cf.domain, cf.options(), sc, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return emit(nil, d, &cf)
}

// emit routes output to terminal / JSON / report file.
func emit(res *analyze.Result, d *diff.Result, cf *commonFlags) int {
	pal := cf.palette()

	if cf.jsonOut {
		var err error
		if d != nil {
			err = report.JSONDiff(os.Stdout, d)
		} else {
			err = report.JSON(os.Stdout, res)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	} else if !cf.quiet || cf.reportPath == "" {
		if d != nil {
			report.TerminalDiff(os.Stdout, d, cf.top, pal)
		} else {
			report.Terminal(os.Stdout, res, cf.top, pal)
		}
	}

	if cf.reportPath != "" {
		if err := writeReport(cf.reportPath, res, d, cf.top); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing report: %v\n", err)
			return 1
		}
		if !cf.quiet {
			fmt.Fprintf(os.Stderr, "wrote %s\n", cf.reportPath)
		}
	}
	return 0
}

func writeReport(path string, res *analyze.Result, d *diff.Result, top int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// diff reports render as HTML/MD via the embedded t1 result for now.
	r := res
	if r == nil && d != nil {
		r = d.T1
	}
	if r == nil {
		return fmt.Errorf("nothing to report")
	}
	if strings.HasSuffix(strings.ToLower(path), ".md") {
		return report.Markdown(f, r, top)
	}
	return report.HTML(f, r, top)
}

func showPayload(w io.Writer, req *features.ScoreRequest, transmits bool) {
	fmt.Fprintln(w, "\n──── OUTBOUND FEATURE PAYLOAD (audit) ─────────────────────────")
	if transmits {
		fmt.Fprintln(w, "This EXACT JSON is what will be sent to the server. Nothing else.")
	} else {
		fmt.Fprintln(w, "OFFLINE: this payload is built locally and is NOT transmitted.")
		fmt.Fprintln(w, "Shown so you can verify what hybrid mode WOULD send.")
	}
	b := prettyPayload(req)
	fmt.Fprintln(w, b)
	fmt.Fprintln(w, "──────────────────────────────────────────────────────────────")
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func printLoad(w io.Writer, r *parse.Report) {
	if r == nil {
		return
	}
	fmt.Fprintf(w, "loaded sources: %s\n", strings.Join(nonEmpty(r.Sources), ", "))
	for k, v := range r.Counts {
		if v > 0 {
			fmt.Fprintf(w, "  %-12s %d\n", k, v)
		}
	}
	fmt.Fprintf(w, "  edges: %d  dangling: %d  unknown-edge-types: %d\n", r.Edges, r.Dangling, r.UnknownEdges)
	for _, wn := range r.Warnings {
		fmt.Fprintf(w, "  warn: %s\n", wn)
	}
}

func nonEmpty(ss []string) []string {
	out := ss[:0]
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

var _ = synth.DomainSID // keep synth importable for check
