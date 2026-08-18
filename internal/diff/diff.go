// Package diff compares two snapshots (t0 -> t1) and flags which change opened a
// new, undetected path to the crown objective (F8).
package diff

import (
	"context"
	"fmt"
	"sort"

	"github.com/harbingerlabs/harbinger-cli/internal/analyze"
	"github.com/harbingerlabs/harbinger-cli/internal/hvt"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/pathfind"
	"github.com/harbingerlabs/harbinger-cli/internal/score"
)

// OpenedPath is a crown path present at t1 but not t0 (a newly-exposed route).
type OpenedPath struct {
	TargetName       string
	Risk             float64
	Evasion          float64
	Hops             int
	BlindSpot        bool
	Steps            []analyze.Step
	ResponsibleEdges []analyze.Step // the edges added since t0 that this path relies on
}

// Change is one edge that appeared or disappeared between the two collections,
// together with every route it accounts for.
//
// Routes are the wrong unit for a second run. A single Domain Admin signing in
// to a different workstation opens a route from every principal who can reach
// that machine — ten near-identical rows describing one event, which is not a
// new exposure at all but the same one, relocated. Meanwhile the change that
// matters (someone granting DCSync to a service account "temporarily") is one
// route and gets pushed off the end of the list.
//
// Grouping by cause puts the count next to the event instead: "one change,
// ten routes". It is the same information in the order an MSP needs it.
type Change struct {
	Step analyze.Step
	// Structural marks a change to configuration — a permission granted or
	// revoked, a group membership edited. Somebody did it on purpose and it
	// persists. A session is the opposite: an observation of who happened to be
	// signed in when the directory was read, which differs on every collection.
	// Both matter, but only one is news.
	Structural bool
	Routes     int
	Risk       float64
	Example    OpenedPath
}

// Result is the diff outcome.
type Result struct {
	DomainMismatch bool
	DomainT0       string
	DomainT1       string
	AddedEdges     int
	RemovedEdges   int

	// Opened: routes to the crown that exist at t1 and did not at t0.
	Opened []OpenedPath
	// Closed: routes that existed at t0 and are gone at t1 — the evidence that
	// a fix actually landed. Without this, a second run has nothing to show.
	Closed []OpenedPath

	// OpenedBy and ClosedBy are the same routes grouped by the change that
	// caused them, structural changes first. This is what a second run should
	// lead with.
	OpenedBy []Change
	ClosedBy []Change

	RiskOpened float64
	RiskClosed float64

	T0 *analyze.Result
	T1 *analyze.Result
}

// edgeSig is a snapshot-stable edge signature (SIDs are stable across snapshots).
func edgeSig(from, to string, t parse.EdgeType) string { return from + "|" + to + "|" + string(t) }

// Compare runs the pipeline on both snapshots and diffs at the path level.
// domainScope restricts both sides to one directory (see hvt.ResolveScoped).
func Compare(ctx context.Context, g0, g1 *parse.Graph, load0, load1 *parse.Report, override []string, domainScope string, opt pathfind.Options, scorer score.Scorer, clientVer string) (*Result, error) {
	res0, err := hvt.ResolveScoped(g0, override, domainScope)
	if err != nil {
		return nil, fmt.Errorf("t0: %w", err)
	}
	res1, err := hvt.ResolveScoped(g1, override, domainScope)
	if err != nil {
		return nil, fmt.Errorf("t1: %w", err)
	}

	out := &Result{}
	// Comparing two different clients' directories produces confident nonsense,
	// so identify each side by its largest domain and say so loudly on mismatch.
	if len(res0.Domains) > 0 {
		out.DomainT0 = domainLabel(res0.Domains[0])
	}
	if len(res1.Domains) > 0 {
		out.DomainT1 = domainLabel(res1.Domains[0])
	}
	if len(res0.Domains) > 0 && len(res1.Domains) > 0 && res0.Domains[0].SID != res1.Domains[0].SID {
		out.DomainMismatch = true
	}

	// Edge-set delta.
	e0 := map[string]bool{}
	for _, e := range g0.Edges {
		e0[edgeSig(e.From, e.To, e.Type)] = true
	}
	e1 := map[string]bool{}
	for _, e := range g1.Edges {
		e1[edgeSig(e.From, e.To, e.Type)] = true
	}
	for s := range e1 {
		if !e0[s] {
			out.AddedEdges++
		}
	}
	for s := range e0 {
		if !e1[s] {
			out.RemovedEdges++
		}
	}

	// Score both snapshots. Scoring t0 as well is what lets us report what was
	// FIXED, not just what broke — the half of the diff that earns a second run.
	t0res, _, err := analyze.Run(ctx, g0, load0, override, domainScope, opt, scorer, clientVer)
	if err != nil {
		return nil, fmt.Errorf("scoring t0: %w", err)
	}
	t1res, _, err := analyze.Run(ctx, g1, load1, override, domainScope, opt, scorer, clientVer)
	if err != nil {
		return nil, fmt.Errorf("scoring t1: %w", err)
	}
	out.T0, out.T1 = t0res, t1res

	// Both sides index every Tier Zero route, not only crown ones. Indexing a
	// narrower set than the comparison walks makes a route that exists on both
	// sides look new on one of them.
	t0keys := map[string]bool{}
	for _, sp := range t0res.Paths {
		t0keys[pathKeyFromSteps(sp.Steps)] = true
	}
	t1keys := map[string]bool{}
	for _, sp := range t1res.Paths {
		t1keys[pathKeyFromSteps(sp.Steps)] = true
	}

	// Every Tier Zero objective counts, not only the crown. A newly granted
	// DCSync reaches the domain object rather than the Domain Admins group, so
	// filtering to the crown dropped the most serious change a diff can report
	// — the analysis ranked it first and the diff did not mention it.
	for _, sp := range t1res.Paths {
		if t0keys[pathKeyFromSteps(sp.Steps)] {
			continue
		}
		op := toOpened(sp)
		for _, st := range sp.Steps {
			if !e0[edgeSig(st.FromID, st.ToID, st.Edge)] {
				op.ResponsibleEdges = append(op.ResponsibleEdges, st)
			}
		}
		out.Opened = append(out.Opened, op)
		out.RiskOpened += sp.Risk
	}

	for _, sp := range t0res.Paths {
		if t1keys[pathKeyFromSteps(sp.Steps)] {
			continue
		}
		cp := toOpened(sp)
		// The edges that disappeared are the change that closed this route.
		for _, st := range sp.Steps {
			if !e1[edgeSig(st.FromID, st.ToID, st.Edge)] {
				cp.ResponsibleEdges = append(cp.ResponsibleEdges, st)
			}
		}
		out.Closed = append(out.Closed, cp)
		out.RiskClosed += sp.Risk
	}

	rank := func(ps []OpenedPath) {
		sort.SliceStable(ps, func(i, j int) bool {
			if ps[i].BlindSpot != ps[j].BlindSpot {
				return ps[i].BlindSpot
			}
			return ps[i].Risk > ps[j].Risk
		})
	}
	rank(out.Opened)
	rank(out.Closed)
	out.OpenedBy = groupByCause(out.Opened)
	out.ClosedBy = groupByCause(out.Closed)
	return out, nil
}

// groupByCause collapses routes onto the edges responsible for them.
// Structural changes sort above observational ones, then by risk, so a granted
// permission is never pushed off the end of the report by session churn.
func groupByCause(paths []OpenedPath) []Change {
	byEdge := map[string]*Change{}
	var order []string
	for _, p := range paths {
		for _, st := range p.ResponsibleEdges {
			k := edgeSig(st.FromID, st.ToID, st.Edge)
			c, ok := byEdge[k]
			if !ok {
				c = &Change{Step: st, Structural: st.Edge != parse.HasSession, Example: p}
				byEdge[k] = c
				order = append(order, k)
			}
			c.Routes++
			c.Risk += p.Risk
			if p.Risk > c.Example.Risk {
				c.Example = p
			}
		}
	}
	out := make([]Change, 0, len(order))
	for _, k := range order {
		out = append(out, *byEdge[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Structural != out[j].Structural {
			return out[i].Structural
		}
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].Routes > out[j].Routes // determinism
	})
	return out
}

func toOpened(sp analyze.ScoredPath) OpenedPath {
	return OpenedPath{
		TargetName: sp.TargetName,
		Risk:       sp.Risk,
		Evasion:    sp.Evasion,
		Hops:       sp.Hops,
		BlindSpot:  sp.BlindSpot,
		Steps:      sp.Steps,
	}
}

func domainLabel(d hvt.Domain) string {
	if d.Name != "" {
		return d.Name
	}
	return d.SID
}

func pathKeyFromSteps(steps []analyze.Step) string {
	if len(steps) == 0 {
		return ""
	}
	k := steps[0].FromID + ">"
	for _, s := range steps {
		k += s.ToID + ">"
	}
	return k
}
