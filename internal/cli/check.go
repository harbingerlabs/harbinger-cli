package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/adexplorer"
	"github.com/harbingerlabs/harbinger-cli/internal/analyze"
	"github.com/harbingerlabs/harbinger-cli/internal/diff"
	"github.com/harbingerlabs/harbinger-cli/internal/features"
	"github.com/harbingerlabs/harbinger-cli/internal/load"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/pathfind"
	"github.com/harbingerlabs/harbinger-cli/internal/score"
	"github.com/harbingerlabs/harbinger-cli/internal/synth"
)

// CmdCheck runs a self-test on a synthetic graph and verifies the privacy
// invariant end-to-end (no cleartext identifiers in the outbound payload).
func CmdCheck(args []string, version string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	filler := fs.Int("filler", 0, "synthetic filler principals (scale smoke test)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	fmt.Println("harbinger self-test — synthetic forest (no file, no network)")
	dir, err := os.MkdirTemp("", "harbinger-check-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [FAIL] tempdir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(dir)

	ok := true
	step := func(name string, fn func() error) {
		if err := fn(); err != nil {
			ok = false
			fmt.Printf("  [FAIL] %s: %v\n", name, err)
		} else {
			fmt.Printf("  [PASS] %s\n", name)
		}
	}

	var g *parse.Graph
	var res *analyze.Result
	var req *features.ScoreRequest

	step("generate synthetic export", func() error {
		return synth.WriteDir(dir, *filler)
	})
	step("ingest (BloodHound parse -> graph)", func() error {
		var e error
		g, _, e = parse.Ingest(dir)
		if e != nil {
			return e
		}
		if len(g.Nodes) == 0 {
			return fmt.Errorf("no nodes")
		}
		return nil
	})
	step("analyze (pathfind + offline score)", func() error {
		load := &parse.Report{}
		var e error
		res, req, e = analyze.Run(context.Background(), g, load, nil, "", pathfind.Default(), score.Distilled{}, version)
		return e
	})
	step("crown path to Domain Admins found", func() error {
		if res == nil || len(res.Paths) == 0 {
			return fmt.Errorf("no attack path ranked")
		}
		for _, p := range res.Paths {
			if p.IsCrown {
				return nil
			}
		}
		return fmt.Errorf("crown not surfaced")
	})
	step("PRIVACY: no cleartext identifiers in outbound payload", func() error {
		return assertNoLeak(g, req)
	})

	// The .dat path is exercised here so an MSP can prove this binary reads AD
	// Explorer snapshots correctly BEFORE pointing it at a client's directory.
	snapPath := filepath.Join(dir, "snapshot.dat")
	var snapGraph *parse.Graph
	step("AD Explorer snapshot: write + read back", func() error {
		if e := adexplorer.SynthWriteFile(snapPath); e != nil {
			return e
		}
		var rep *parse.Report
		var e error
		snapGraph, rep, e = adexplorer.Ingest(snapPath)
		if e != nil {
			return e
		}
		if len(snapGraph.Nodes) == 0 {
			return fmt.Errorf("no objects decoded")
		}
		if len(rep.Gaps) == 0 {
			return fmt.Errorf("snapshot collection gaps were not declared")
		}
		return nil
	})
	step("AD Explorer snapshot: ACL edges recovered from security descriptors", func() error {
		for _, e := range snapGraph.Edges {
			if e.Type == parse.GenericAll {
				return nil
			}
		}
		return fmt.Errorf("no ACL edge derived — the DACL parser is not working")
	})
	step("AD Explorer snapshot: analyzed end-to-end", func() error {
		r, _, e := analyze.Run(context.Background(), snapGraph, &parse.Report{}, nil, "",
			pathfind.Default(), score.Distilled{}, version)
		if e != nil {
			return e
		}
		if len(r.Paths) == 0 {
			return fmt.Errorf("no path ranked from the snapshot")
		}
		return nil
	})
	step("input auto-detection (folder / json / .dat)", func() error {
		if _, _, e := load.Any(snapPath); e != nil {
			return fmt.Errorf("snapshot not auto-detected: %w", e)
		}
		if _, _, e := load.Any(dir); e != nil {
			return fmt.Errorf("directory not auto-detected: %w", e)
		}
		return nil
	})
	step("malformed input fails cleanly (no crash)", func() error {
		bad := filepath.Join(dir, "corrupt.dat")
		if e := os.WriteFile(bad, []byte("win-ad-objGARBAGE\x00\x00"), 0o600); e != nil {
			return e
		}
		if _, _, e := load.Any(bad); e == nil {
			return fmt.Errorf("a corrupt snapshot was accepted")
		}
		empty := filepath.Join(dir, "empty.json")
		if e := os.WriteFile(empty, nil, 0o600); e != nil {
			return e
		}
		if _, _, e := load.Any(empty); e == nil {
			return fmt.Errorf("an empty file was accepted")
		}
		return nil
	})
	step("t0 -> t1 diff", func() error {
		d, e := diff.Compare(context.Background(), g, snapGraph, &parse.Report{}, &parse.Report{},
			nil, "", pathfind.Default(), score.Distilled{}, version)
		if e != nil {
			return e
		}
		if !d.DomainMismatch {
			return fmt.Errorf("two different directories were not flagged as a mismatch")
		}
		// Same graph on both sides: nothing opened, nothing closed.
		same, e := diff.Compare(context.Background(), g, g, &parse.Report{}, &parse.Report{},
			nil, "", pathfind.Default(), score.Distilled{}, version)
		if e != nil {
			return e
		}
		if len(same.Opened) != 0 || len(same.Closed) != 0 {
			return fmt.Errorf("diffing a snapshot against itself reported %d opened / %d closed",
				len(same.Opened), len(same.Closed))
		}
		return nil
	})

	if ok {
		fmt.Printf("\nALL CHECKS PASS — pipeline healthy, privacy boundary intact.\n")
		if res != nil && len(res.Paths) > 0 {
			fmt.Printf("  (found %d paths; top risk %.3f to %s)\n", len(res.Paths), res.Paths[0].Risk, res.Paths[0].TargetName)
		}
		return 0
	}
	fmt.Printf("\nSELF-TEST FAILED\n")
	return 1
}

// assertNoLeak is the core trust test: serialize the outbound payload and prove
// it contains none of the graph's identity-bearing strings.
func assertNoLeak(g *parse.Graph, req *features.ScoreRequest) error {
	payload := strings.ToLower(prettyPayload(req))
	for id, n := range g.Nodes {
		if id != "" && strings.Contains(payload, strings.ToLower(id)) {
			return fmt.Errorf("SID %q leaked into payload", id)
		}
		if n.Name != "" && strings.Contains(payload, strings.ToLower(n.Name)) {
			return fmt.Errorf("name %q leaked into payload", n.Name)
		}
		if n.DomainSID != "" && strings.Contains(payload, strings.ToLower(n.DomainSID)) {
			return fmt.Errorf("domain SID %q leaked into payload", n.DomainSID)
		}
	}
	return nil
}
