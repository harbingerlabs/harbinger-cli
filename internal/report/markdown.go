package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/analyze"
)

// Markdown writes a shareable Markdown report (for --report out.md).
func Markdown(w io.Writer, r *analyze.Result, top int) error {
	var b strings.Builder
	blind := 0
	for _, p := range r.Paths {
		if p.BlindSpot {
			blind++
		}
	}
	sum := Summarize(r)

	fmt.Fprintf(&b, "# Harbinger — Attack-Path Exposure\n\n")
	fmt.Fprintf(&b, "Crown objective: **%s**\n\n", r.CrownName)
	fmt.Fprintf(&b, "> **%s**\n\n", sum.Headline)

	fmt.Fprintf(&b, "## What this means\n\n%s\n\n", sum.Meaning)
	fmt.Fprintf(&b, "## Do this first\n\n%s\n\n", sum.Action)
	if sum.Effort != "" {
		fmt.Fprintf(&b, "_%s_\n\n", sum.Effort)
	}

	if len(sum.Scope) > 0 {
		fmt.Fprintf(&b, "## Scope of this run\n\n")
		for _, sc := range sum.Scope {
			fmt.Fprintf(&b, "- %s\n", sc)
		}
		b.WriteString("\n")
	}
	if len(sum.Gaps) > 0 {
		fmt.Fprintf(&b, "## What this run could NOT see\n\n")
		fmt.Fprintf(&b, "A route that was not collected is invisible, not absent. These gaps bound every number above:\n\n")
		for _, gp := range sum.Gaps {
			fmt.Fprintf(&b, "- %s\n", gp)
		}
		b.WriteString("\n")
	}
	_ = blind

	if len(r.Paths) > 0 {
		fmt.Fprintf(&b, "## Top %d paths (ranked by reachable-and-undetected risk)\n\n", min(top, len(r.Paths)))
		fmt.Fprintf(&b, "| # | risk | hops | evasion | starts | target | path |\n|---|---|---|---|---|---|---|\n")
		for i, p := range r.Paths {
			if i >= top {
				break
			}
			ev := fmt.Sprintf("%.0f%%", p.Evasion*100)
			if p.BlindSpot {
				ev += " 🔴"
			}
			starts := "1"
			if p.StartCount > 1 {
				starts = fmt.Sprintf("%d", p.StartCount)
			}
			fmt.Fprintf(&b, "| %d | %.3f | %d | %s | %s | %s%s | %s |\n",
				p.Rank, p.Risk, p.Hops, ev, starts, p.TargetName, crown(p.IsCrown), chainMD(p))
		}
		b.WriteString("\n")
	}

	if r.TopFix != nil {
		f := r.TopFix
		fmt.Fprintf(&b, "## Highest-impact fix — the technical change\n\n"+
			"%s\n\nCuts %d ranked paths (%.3f risk removed; %s, `%s`).\n\n"+
			"Check this against the account's legitimate use before changing it; if it is "+
			"required, reduce its scope instead and re-run to confirm the routes closed.\n\n",
			Remediation(f.Edge, f.Label, f.FromName, f.ToName),
			f.PathsKilled, f.RiskRemoved, f.Label, f.Edge)
	}

	mode := "Offline — zero network calls; no data left this machine."
	if r.Transmitted {
		mode = "Hybrid — only anonymized tokenized features were transmitted; raw AD identities never left this machine."
	}
	fmt.Fprintf(&b, "---\n\n_Privacy: %s Read-only; no credentials; live AD never contacted. Model `%s`, tier %s. → harbingerlabs.ai_\n",
		mode, r.ModelVersion, r.Tier)

	_, err := io.WriteString(w, b.String())
	return err
}

func chainMD(p analyze.ScoredPath) string {
	if len(p.Steps) == 0 {
		return ""
	}
	var parts []string
	parts = append(parts, "`"+p.Steps[0].FromName+"`")
	for _, s := range p.Steps {
		parts = append(parts, fmt.Sprintf("—[%s]→ `%s`", s.Edge, s.ToName))
	}
	return strings.Join(parts, " ")
}

func crown(b bool) string {
	if b {
		return " ★"
	}
	return ""
}
