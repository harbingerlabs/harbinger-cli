// Package analyze orchestrates the local pipeline and assembles the final,
// human-facing result. Token->identity re-mapping happens here, locally.
package analyze

import (
	"context"
	"sort"

	"github.com/harbingerlabs/harbinger-cli/internal/features"
	"github.com/harbingerlabs/harbinger-cli/internal/hvt"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/pathfind"
	"github.com/harbingerlabs/harbinger-cli/internal/score"
)

// Step is one rendered hop with real identities (LOCAL rendering only).
type Step struct {
	FromID   string         `json:"from_id"`
	FromName string         `json:"from_name"`
	ToID     string         `json:"to_id"`
	ToName   string         `json:"to_name"`
	Edge     parse.EdgeType `json:"edge"`
	Label    string         `json:"label"`
	Detect   float64        `json:"detect"`
}

// ScoredPath is one ranked attack path with identities re-attached.
type ScoredPath struct {
	Rank       int     `json:"rank"`
	TargetID   string  `json:"target_id"`
	TargetName string  `json:"target_name"`
	TargetKind string  `json:"target_kind"`
	IsCrown    bool    `json:"is_crown"`
	Hops       int     `json:"hops"`
	Success    float64 `json:"success"`
	Evasion    float64 `json:"evasion"`
	Risk       float64 `json:"risk"`       // reachable-AND-undetected
	BlindSpot  bool    `json:"blind_spot"` // evasion >= 0.5 => detection unlikely
	// StartCount is how many distinct principals can walk this same route. Every
	// member of a group that holds a permission produces an identical route with
	// an identical fix; they are reported as one row and a number.
	StartCount int    `json:"start_count"`
	Steps      []Step `json:"steps"`
}

// Fix is the single highest-impact remediation.
type Fix struct {
	Edge        parse.EdgeType `json:"edge"`
	Label       string         `json:"label"`
	FromName    string         `json:"from_name"`
	ToName      string         `json:"to_name"`
	PathsKilled int            `json:"paths_killed"`
	RiskRemoved float64        `json:"risk_removed"`
}

// Result is everything the report renderers consume.
type Result struct {
	CrownID      string        `json:"crown_id"`
	CrownName    string        `json:"crown_name"`
	Paths        []ScoredPath  `json:"paths"`
	TopFix       *Fix          `json:"top_fix"`
	Load         *parse.Report `json:"load"`
	ScorerName   string        `json:"scorer"`
	Transmitted  bool          `json:"transmitted"`
	ModelVersion string        `json:"model_version"`
	Tier         string        `json:"tier"`

	// Domains present in the input, largest first. More than one means the
	// export spans a forest or several tenants.
	Domains []hvt.Domain `json:"domains"`
	// Scope is the domain the run was restricted to, or "" for all of them.
	Scope string `json:"scope"`
}

// Assemble joins scored tokens back to concrete paths and ranks them.
func Assemble(g *parse.Graph, res *hvt.Resolved, paths []pathfind.Path, m *features.Mapping, sc *score.Response, load *parse.Report, scorer score.Scorer) *Result {
	byToken := map[string]score.PathScore{}
	for _, s := range sc.Scores {
		byToken[s.Token] = s
	}
	out := &Result{
		CrownID:      res.Crown,
		CrownName:    res.CrownName,
		Load:         load,
		ScorerName:   scorer.Name(),
		Transmitted:  scorer.Transmits(),
		ModelVersion: sc.ModelVersion,
		Tier:         sc.Tier,
	}

	for tok, idx := range m.PathIndex {
		s, ok := byToken[tok]
		if !ok || idx >= len(paths) {
			continue
		}
		p := paths[idx]
		sp := ScoredPath{
			TargetID:   p.Target(),
			TargetName: nameOf(g, p.Target()),
			TargetKind: kindOf(g, p.Target()),
			IsCrown:    p.Target() == res.Crown,
			Hops:       len(p.Edges),
			Success:    s.SuccessProb,
			Evasion:    s.EvasionProb,
			Risk:       s.CombinedRank,
			BlindSpot:  s.EvasionProb >= 0.5,
			StartCount: p.StartCount,
		}
		// Routes to non-crown objectives are found by a search that does not
		// collapse duplicates, so they carry no count. One principal walks a
		// route by definition; reporting zero reads as "nobody can".
		if sp.StartCount < 1 {
			sp.StartCount = 1
		}
		for _, e := range p.Edges {
			sp.Steps = append(sp.Steps, Step{
				FromID: e.From, FromName: nameOf(g, e.From),
				ToID: e.To, ToName: nameOf(g, e.To),
				Edge:   e.Type,
				Label:  e.Type.Profile().Label,
				Detect: e.Type.Profile().Detection,
			})
		}
		out.Paths = append(out.Paths, sp)
	}

	sort.SliceStable(out.Paths, func(i, j int) bool {
		if out.Paths[i].Risk != out.Paths[j].Risk {
			return out.Paths[i].Risk > out.Paths[j].Risk
		}
		return out.Paths[i].Hops < out.Paths[j].Hops
	})
	for i := range out.Paths {
		out.Paths[i].Rank = i + 1
	}
	out.TopFix = topFix(g, out.Paths)
	return out
}

// topFix picks the edge whose removal eliminates the most total risk across the
// ranked paths — the single highest-impact remediation (F7).
func topFix(g *parse.Graph, paths []ScoredPath) *Fix {
	type agg struct {
		count int
		risk  float64
		step  Step
	}
	byEdge := map[string]*agg{}
	for _, p := range paths {
		for _, st := range p.Steps {
			// Structural edges (MemberOf/Contains) are rarely "removable" fixes;
			// weight toward abusable control edges.
			if st.Edge == parse.MemberOf || st.Edge == parse.Contains {
				continue
			}
			k := st.FromID + "|" + st.ToID + "|" + string(st.Edge)
			a := byEdge[k]
			if a == nil {
				a = &agg{step: st}
				byEdge[k] = a
			}
			a.count++
			a.risk += p.Risk
		}
	}
	// Deterministic selection: highest total risk removed, then most paths cut,
	// then a stable key — never map iteration order.
	keys := make([]string, 0, len(byEdge))
	for k := range byEdge {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var best *agg
	for _, k := range keys {
		a := byEdge[k]
		if best == nil || a.risk > best.risk || (a.risk == best.risk && a.count > best.count) {
			best = a
		}
	}
	if best == nil {
		return nil
	}
	return &Fix{
		Edge:        best.step.Edge,
		Label:       best.step.Label,
		FromName:    best.step.FromName,
		ToName:      best.step.ToName,
		PathsKilled: best.count,
		RiskRemoved: best.risk,
	}
}

// Run is the end-to-end local pipeline used by `analyze`. domainScope restricts
// the objective to a single directory (empty = the whole input).
func Run(ctx context.Context, g *parse.Graph, load *parse.Report, override []string, domainScope string, opt pathfind.Options, scorer score.Scorer, clientVer string) (*Result, *features.ScoreRequest, error) {
	res, err := hvt.ResolveScoped(g, override, domainScope)
	if err != nil {
		return nil, nil, err
	}
	paths := pathfind.Find(g, res, opt)
	req, m := features.Extract(g, paths, clientVer)
	sc, err := scorer.Score(ctx, req)
	if err != nil {
		return nil, req, err
	}
	out := Assemble(g, res, paths, m, sc, load, scorer)
	out.Domains = res.Domains
	out.Scope = res.Scope
	return out, req, nil
}

// nameOf renders a principal for a human. A dangling SID becomes a well-known
// name or an explicit "unresolved" label — never a raw identifier the reader
// cannot judge.
func nameOf(g *parse.Graph, id string) string {
	if n := g.Node(id); n != nil {
		return parse.DisplayName(n)
	}
	if wk := parse.WellKnownName(id); wk != "" {
		return wk + " (not in this collection)"
	}
	return "unresolved principal " + id
}
func kindOf(g *parse.Graph, id string) string {
	if n := g.Node(id); n != nil {
		return string(n.Kind)
	}
	return string(parse.KindUnknown)
}
