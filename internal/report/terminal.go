// Package report renders analysis results to terminal, JSON, and self-contained
// HTML. HTML makes ZERO external calls (inline CSS, no fonts/images/scripts).
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/analyze"
	"github.com/harbingerlabs/harbinger-cli/internal/diff"
)

// Palette toggles ANSI color.
type Palette struct{ Color bool }

func (p Palette) c(code, s string) string {
	if !p.Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (p Palette) bold(s string) string   { return p.c("1", s) }
func (p Palette) red(s string) string    { return p.c("31", s) }
func (p Palette) green(s string) string  { return p.c("32", s) }
func (p Palette) yellow(s string) string { return p.c("33", s) }
func (p Palette) dim(s string) string    { return p.c("2", s) }

// Terminal writes the human-facing terminal report.
func Terminal(w io.Writer, r *analyze.Result, top int, pal Palette) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, pal.bold("  HARBINGER — attack-path exposure analysis"))
	fmt.Fprintln(w, pal.dim("  ────────────────────────────────────────────────────────"))

	// Load summary.
	if r.Load != nil {
		fmt.Fprintf(w, "  Loaded %s across %d edge(s)%s\n",
			countStr(r.Load), r.Load.Edges, danglingStr(r.Load))
	}
	fmt.Fprintf(w, "  Crown objective: %s\n", pal.bold(r.CrownName))

	blind := 0
	for _, p := range r.Paths {
		if p.BlindSpot {
			blind++
		}
	}

	// Plain-English layer, first, for the person deciding whether this gets
	// scheduled rather than the one who will do the work.
	sum := Summarize(r)
	fmt.Fprintln(w)
	switch sum.Verdict {
	case "exposed":
		fmt.Fprintf(w, "  %s\n", pal.red(pal.bold("⚠  "+sum.Headline)))
	case "clear", "watch":
		fmt.Fprintf(w, "  %s\n", pal.green(sum.Headline))
	default:
		fmt.Fprintf(w, "  %s\n", pal.yellow(sum.Headline))
	}
	fmt.Fprintln(w)
	for _, line := range wrapText(sum.Meaning, 68) {
		fmt.Fprintf(w, "  %s\n", pal.dim(line))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", pal.bold("Do this first"))
	for _, line := range wrapText(sum.Action, 68) {
		fmt.Fprintf(w, "     %s\n", line)
	}
	if sum.Effort != "" {
		for _, line := range wrapText(sum.Effort, 68) {
			fmt.Fprintf(w, "     %s\n", pal.dim(line))
		}
	}
	if len(sum.Scope) > 0 {
		fmt.Fprintln(w)
		for _, sc := range sum.Scope {
			for i, line := range wrapText(sc, 68) {
				prefix := "  · "
				if i > 0 {
					prefix = "    "
				}
				fmt.Fprintf(w, "%s%s\n", prefix, pal.dim(line))
			}
		}
	}
	if len(sum.Gaps) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", pal.yellow(pal.bold("What this run could NOT see")))
		for _, gp := range sum.Gaps {
			for i, line := range wrapText(gp, 66) {
				prefix := "     - "
				if i > 0 {
					prefix = "       "
				}
				fmt.Fprintf(w, "%s%s\n", prefix, pal.yellow(line))
			}
		}
	}

	// Top paths.
	if len(r.Paths) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", pal.bold(fmt.Sprintf("Top %d paths (ranked by reachable-and-undetected risk)", min(top, len(r.Paths)))))
		for i, p := range r.Paths {
			if i >= top {
				break
			}
			seen := pal.green(fmt.Sprintf("%.0f%% evasion", p.Evasion*100))
			if p.BlindSpot {
				seen = pal.red(fmt.Sprintf("%.0f%% evasion — BLIND SPOT", p.Evasion*100))
			}
			star := ""
			if p.IsCrown {
				star = pal.yellow(" ★crown")
			}
			fmt.Fprintf(w, "\n  %s  risk %s  |  %d hops  |  %s%s\n",
				pal.bold(fmt.Sprintf("#%d", p.Rank)),
				pal.bold(fmt.Sprintf("%.3f", p.Risk)), p.Hops, seen, star)
			fmt.Fprintf(w, "     %s\n", renderChain(p, pal))
			if p.StartCount > 1 {
				fmt.Fprintf(w, "     %s\n", pal.dim(fmt.Sprintf(
					"%d other principals can start this same route — one fix closes it for all of them.",
					p.StartCount-1)))
			}
		}
	}

	// Top fix.
	if r.TopFix != nil {
		f := r.TopFix
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", pal.bold("Highest-impact fix"))
		fmt.Fprintf(w, "     %s\n", pal.bold(Remediation(f.Edge, f.Label, f.FromName, f.ToName)))
		fmt.Fprintf(w, "     %s\n", pal.dim(fmt.Sprintf("cuts %d of the ranked paths (%.3f total risk removed) — %s (%s)",
			f.PathsKilled, f.RiskRemoved, f.Label, f.Edge)))
	}

	footer(w, r, pal)
}

func renderChain(p analyze.ScoredPath, pal Palette) string {
	if len(p.Steps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(pal.bold(p.Steps[0].FromName))
	for _, s := range p.Steps {
		arrow := "─"
		if s.Detect < 0.3 {
			arrow = pal.red("⇢") // quiet edge
		}
		b.WriteString(fmt.Sprintf(" %s[%s]%s ", arrow, string(s.Edge), arrow))
		b.WriteString(pal.bold(s.ToName))
	}
	return b.String()
}

func footer(w io.Writer, r *analyze.Result, pal Palette) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, pal.dim("  ────────────────────────────────────────────────────────"))
	mode := pal.green("OFFLINE — no data left this machine")
	if r.Transmitted {
		mode = pal.yellow("HYBRID — only anonymized tokenized features were transmitted (see --show-payload)")
	}
	fmt.Fprintf(w, "  Scorer: %s (%s) | tier: %s\n", r.ScorerName, r.ModelVersion, r.Tier)
	fmt.Fprintf(w, "  Privacy: %s\n", mode)
	fmt.Fprintln(w, pal.dim("  Scores are structural priors, not a guarantee. The offline model is a"))
	fmt.Fprintln(w, pal.dim("  distilled approximation; the server model is ρ-calibrated. Read-only; no"))
	fmt.Fprintln(w, pal.dim("  credentials used; live AD never contacted.  → harbingerlabs.ai"))
	fmt.Fprintln(w)
}

// TerminalDiff renders the diff result.
func TerminalDiff(w io.Writer, d *diff.Result, top int, pal Palette) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, pal.bold("  HARBINGER — snapshot diff (t0 → t1)"))
	fmt.Fprintln(w, pal.dim("  ────────────────────────────────────────────────────────"))
	if d.DomainMismatch {
		fmt.Fprintln(w, pal.red(pal.bold("  ⚠  These two snapshots are of DIFFERENT directories — this diff is meaningless.")))
		fmt.Fprintf(w, "     %s\n", pal.red(fmt.Sprintf("t0 = %s   t1 = %s", d.DomainT0, d.DomainT1)))
		fmt.Fprintln(w, pal.dim("     Compare two snapshots of the same client, or pass --domain to pin one."))
	} else if d.DomainT1 != "" {
		fmt.Fprintf(w, "  Directory: %s\n", pal.bold(d.DomainT1))
	}
	fmt.Fprintf(w, "  Edge changes: %s added, %s removed\n",
		pal.green(fmt.Sprintf("+%d", d.AddedEdges)), pal.red(fmt.Sprintf("-%d", d.RemovedEdges)))

	// Progress first: what the last round of work actually closed.
	if len(d.Closed) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", pal.green(pal.bold(fmt.Sprintf("✔  %d route(s) to a Tier Zero objective were CLOSED since t0 (%.3f risk removed).",
			len(d.Closed), d.RiskClosed))))
		for i, cp := range d.Closed {
			if i >= top {
				fmt.Fprintf(w, "     %s\n", pal.dim(fmt.Sprintf("… and %d more", len(d.Closed)-top)))
				break
			}
			fmt.Fprintf(w, "     %s %s\n", pal.green("−"), pal.dim(renderChainSteps(cp.Steps, Palette{})))
			if len(cp.ResponsibleEdges) > 0 {
				var rs []string
				for _, e := range cp.ResponsibleEdges {
					rs = append(rs, fmt.Sprintf("%s→%s (%s)", e.FromName, e.ToName, e.Edge))
				}
				fmt.Fprintf(w, "       %s %s\n", pal.dim("closed by removing:"), pal.green(strings.Join(rs, ", ")))
			}
		}
	}

	if len(d.Opened) == 0 {
		fmt.Fprintln(w)
		if len(d.Closed) > 0 {
			fmt.Fprintln(w, pal.green("  No change opened a new path to a Tier Zero objective. Net exposure went down."))
		} else {
			fmt.Fprintln(w, pal.green("  No change opened a new path to a Tier Zero objective."))
		}
		if d.T1 != nil {
			footer(w, d.T1, pal)
		}
		return
	}

	// Lead with what changed, not with what it produced. One event can open ten
	// routes, and ten rows describing one event reads as ten problems.
	if len(d.OpenedBy) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", pal.bold(fmt.Sprintf("%d change(s) opened %d route(s) to a Tier Zero objective (%.3f risk added)",
			len(d.OpenedBy), len(d.Opened), d.RiskOpened)))
		for _, c := range d.OpenedBy {
			mark, note := pal.yellow("·"), ""
			if c.Structural {
				mark = pal.red("⚑")
			} else {
				note = pal.dim("  (a session moved — the same exposure, on a different machine)")
			}
			fmt.Fprintf(w, "     %s %s\n", mark,
				Remediation(c.Step.Edge, c.Step.Label, c.Step.FromName, c.Step.ToName))
			fmt.Fprintf(w, "       %s%s\n",
				pal.dim(fmt.Sprintf("%s → %s (%s) · opened %d route(s), %.3f risk",
					c.Step.FromName, c.Step.ToName, c.Step.Edge, c.Routes, c.Risk)), note)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", pal.red(pal.bold(fmt.Sprintf("%d newly-opened path(s) to a Tier Zero objective (%.3f risk added):", len(d.Opened), d.RiskOpened))))
	for i, op := range d.Opened {
		if i >= top {
			break
		}
		tag := ""
		if op.BlindSpot {
			tag = pal.red(" — BLIND SPOT")
		}
		fmt.Fprintf(w, "\n  %s risk %s | %d hops | %.0f%% evasion%s\n",
			pal.bold(fmt.Sprintf("#%d", i+1)), pal.bold(fmt.Sprintf("%.3f", op.Risk)), op.Hops, op.Evasion*100, tag)
		fmt.Fprintf(w, "     %s\n", renderChainSteps(op.Steps, pal))
		if len(op.ResponsibleEdges) > 0 {
			var rs []string
			for _, e := range op.ResponsibleEdges {
				rs = append(rs, fmt.Sprintf("%s→%s (%s)", e.FromName, e.ToName, e.Edge))
			}
			fmt.Fprintf(w, "     %s %s\n", pal.bold("opened by:"), pal.yellow(strings.Join(rs, ", ")))
		}
	}
	if d.T1 != nil {
		footer(w, d.T1, pal)
	}
}

func renderChainSteps(steps []analyze.Step, pal Palette) string {
	if len(steps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(pal.bold(steps[0].FromName))
	for _, s := range steps {
		b.WriteString(fmt.Sprintf(" ─[%s]→ ", string(s.Edge)))
		b.WriteString(pal.bold(s.ToName))
	}
	return b.String()
}

func shortName(s string) string {
	if i := strings.Index(s, "@"); i > 0 {
		return s[:i]
	}
	return s
}
