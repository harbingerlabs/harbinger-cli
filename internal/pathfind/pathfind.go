// Package pathfind finds bounded, pruned attack paths from low-privilege
// principals to High-Value Targets. Edge cost is -log(success), so the cheapest
// path is the most-likely-to-succeed one.
//
// Strategy:
//   - Crown objective: ONE reverse-Dijkstra from the crown yields the cheapest
//     path from every low-priv principal to the crown. We keep the best path per
//     distinct starting principal (this is what a defender wants: "who can reach
//     Domain Admin, and how"). O(E log V) total, not O(starts · Dijkstra).
//   - Other HVTs: a single forward Dijkstra from a virtual super-source wired to
//     all starts gives one representative shortest path to each.
package pathfind

import (
	"container/heap"
	"math"
	"sort"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/hvt"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

const superSource = "" // virtual node wired to every low-priv start

// Path is a concrete attack chain: Nodes[i] --Edges[i]--> Nodes[i+1].
type Path struct {
	Nodes []string
	Edges []parse.Edge
	Cost  float64
	// StartCount is how many distinct principals can walk this same route.
	// Collapsed rows report it so the blast radius survives de-duplication.
	StartCount int
}

// Target is the HVT this path reaches (last node).
func (p Path) Target() string {
	if len(p.Nodes) == 0 {
		return ""
	}
	return p.Nodes[len(p.Nodes)-1]
}

// Key is a stable per-path signature (node sequence). Used locally to build a
// path token; it is never transmitted.
func (p Path) Key() string {
	var b strings.Builder
	for _, n := range p.Nodes {
		b.WriteString(n)
		b.WriteByte('>')
	}
	return b.String()
}

// Options bound the search (perf-critical on large graphs).
type Options struct {
	MaxHops   int // hard cap on path length
	KPerCrown int // max distinct-start paths to keep for the crown
	MaxStarts int // cap number of low-priv starts (0 = all)
}

// Default options tuned to stay well under a second on 25k-node graphs.
func Default() Options { return Options{MaxHops: 12, KPerCrown: 15, MaxStarts: 0} }

// Find returns a de-duplicated, pruned set of candidate paths.
func Find(g *parse.Graph, res *hvt.Resolved, opt Options) []Path {
	if opt.MaxHops == 0 {
		opt = Default()
	}
	starts := lowPrivStarts(g, res, opt.MaxStarts)
	if len(starts) == 0 || res.Crown == "" {
		return nil
	}
	pf := &finder{g: g, starts: starts, startSet: toSet(starts), maxHops: opt.MaxHops}

	var out []Path
	seen := map[string]bool{}
	add := func(p Path, ok bool) {
		if !ok || len(p.Edges) == 0 {
			return
		}
		if k := p.Key(); !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}

	// Crown: best path per starting principal, then the same again per distinct
	// route. One per principal alone answers "who can reach Domain Admin"; it
	// does not answer "what are the ways in", and those are different questions
	// with different remediations. See routesThroughEachEdge.
	crown := pf.pathsToCrown(res.Crown)
	crown = append(crown, pf.routesThroughEachEdge(res.Crown)...)
	crown = collapseByRoute(crown)
	sort.SliceStable(crown, func(i, j int) bool { return crown[i].Cost < crown[j].Cost })
	if opt.KPerCrown > 0 && len(crown) > opt.KPerCrown {
		crown = crown[:opt.KPerCrown]
	}
	for _, p := range crown {
		add(p, true)
	}

	// Other HVTs: one representative shortest path each.
	for _, t := range res.Targets {
		if t == res.Crown {
			continue
		}
		p, ok := pf.dijkstra(t)
		add(p, ok)
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Cost < out[j].Cost })
	return out
}

// lowPrivStarts = enabled User principals that are not themselves Tier Zero.
func lowPrivStarts(g *parse.Graph, res *hvt.Resolved, cap int) []string {
	var s []string
	for id, n := range g.Nodes {
		if n.Kind == parse.KindUser && n.Enabled && !res.TierZero[id] {
			s = append(s, id)
		}
	}
	sort.Strings(s) // determinism
	if cap > 0 && len(s) > cap {
		s = s[:cap]
	}
	return s
}

type finder struct {
	g        *parse.Graph
	starts   []string
	startSet map[string]bool
	maxHops  int
}

// distancesToCrown runs one reverse-Dijkstra from the crown. It returns the
// cost from every node to the crown, and forward[node] = the edge to take FROM
// node heading toward it.
func (f *finder) distancesToCrown(crown string) (map[string]float64, map[string]parse.Edge) {
	forward := map[string]parse.Edge{}
	dist := map[string]float64{crown: 0}
	hops := map[string]int{crown: 0}
	pq := &pqueue{{node: crown, dist: 0}}
	heap.Init(pq)

	for pq.Len() > 0 {
		cur := heap.Pop(pq).(pqItem)
		if cur.dist > dist[cur.node] {
			continue
		}
		if hops[cur.node] >= f.maxHops {
			continue
		}
		// Explore incoming edges: w --e--> cur means from w you can reach cur.
		for _, e := range f.g.In(cur.node) {
			w := e.From
			nd := cur.dist + edgeCost(e.Type)
			if old, ok := dist[w]; !ok || nd < old {
				dist[w] = nd
				forward[w] = e
				hops[w] = hops[cur.node] + 1
				heap.Push(pq, pqItem{node: w, dist: nd})
			}
		}
	}
	return dist, forward
}

// distancesFromStarts runs one forward Dijkstra from the virtual super-source
// wired to every low-privilege start, giving the cheapest cost from any start
// to every reachable node, and the edge used to get there.
func (f *finder) distancesFromStarts() (map[string]float64, map[string]parse.Edge) {
	dist := map[string]float64{superSource: 0}
	prev := map[string]parse.Edge{}
	hops := map[string]int{superSource: 0}
	pq := &pqueue{{node: superSource, dist: 0}}
	heap.Init(pq)

	for pq.Len() > 0 {
		cur := heap.Pop(pq).(pqItem)
		if cur.dist > dist[cur.node] {
			continue
		}
		if hops[cur.node] >= f.maxHops {
			continue
		}
		for _, st := range f.neighbors(cur.node) {
			nd := cur.dist + st.cost
			if old, ok := dist[st.to]; !ok || nd < old {
				dist[st.to] = nd
				prev[st.to] = st.edge
				hops[st.to] = hops[cur.node] + 1
				heap.Push(pq, pqItem{node: st.to, dist: nd})
			}
		}
	}
	return dist, prev
}

// reconstructBackFrom rebuilds the cheapest start->node path from the map that
// distancesFromStarts produced. A node that is itself a start yields the empty
// path, which splices correctly as a route beginning at that node.
func reconstructBackFrom(prev map[string]parse.Edge, node string) (Path, bool) {
	if _, ok := prev[node]; !ok {
		return Path{}, false
	}
	p := reconstructBack(prev, node)
	if len(p.Nodes) == 0 {
		return Path{}, false
	}
	return p, true
}

// pathsToCrown reconstructs the cheapest path from each low-priv start.
func (f *finder) pathsToCrown(crown string) []Path {
	dist, forward := f.distancesToCrown(crown)
	var out []Path
	for _, s := range f.starts {
		if _, ok := dist[s]; !ok || s == crown {
			continue
		}
		if p, ok := reconstructForward(forward, s, crown, f.maxHops); ok {
			out = append(out, p)
		}
	}
	return out
}

// routesThroughEachEdge finds, for every edge, the cheapest route from a
// low-privilege principal to the crown that passes through it.
//
// The per-principal search answers "who can reach Domain Admin" and stops
// there: it returns each principal's single cheapest route. On a real estate
// that hides things. Five helpdesk staff share one group, so they produce five
// near-identical rows; and because the cheapest route from those same five runs
// through one workstation, a second, structurally different route through a
// server with unconstrained delegation is never generated at all — despite
// being the more serious exposure and needing a completely different fix.
//
// Pivoting on edges instead asks "what are the ways in", which is the question
// the remediation actually answers. Two Dijkstras are already available: cost
// from any start to u, and cost from v to the crown. The cheapest route through
// edge u->v is then just the sum, computed for every edge in one pass.
func (f *finder) routesThroughEachEdge(crown string) []Path {
	toCrown, forward := f.distancesToCrown(crown)
	fromStarts, back := f.distancesFromStarts()

	var out []Path
	for _, e := range f.g.Edges {
		du, ok1 := fromStarts[e.From]
		dv, ok2 := toCrown[e.To]
		if !ok1 || !ok2 {
			continue
		}
		if math.IsInf(du, 1) || math.IsInf(dv, 1) {
			continue
		}
		head, ok := reconstructBackFrom(back, e.From)
		if !ok {
			continue
		}
		tail, ok := reconstructForward(forward, e.To, crown, f.maxHops)
		if !ok {
			continue
		}
		p, ok := splice(head, e, tail, f.maxHops)
		if ok {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Cost != out[j].Cost {
			return out[i].Cost < out[j].Cost
		}
		return out[i].Key() < out[j].Key() // determinism
	})
	return out
}

// splice joins start..u, the edge u->v, and v..crown into one simple path.
// A node may not repeat: the two halves are shortest-path trees computed
// independently, so they can overlap, and a route that visits the same
// principal twice is not a route anyone can walk.
func splice(head Path, e parse.Edge, tail Path, maxHops int) (Path, bool) {
	if len(head.Nodes) == 0 || len(tail.Nodes) == 0 {
		return Path{}, false
	}
	seen := make(map[string]bool, len(head.Nodes)+len(tail.Nodes))
	nodes := make([]string, 0, len(head.Nodes)+len(tail.Nodes))
	for _, n := range head.Nodes {
		if seen[n] {
			return Path{}, false
		}
		seen[n] = true
		nodes = append(nodes, n)
	}
	for _, n := range tail.Nodes {
		if seen[n] {
			return Path{}, false
		}
		seen[n] = true
		nodes = append(nodes, n)
	}
	edges := make([]parse.Edge, 0, len(head.Edges)+1+len(tail.Edges))
	edges = append(edges, head.Edges...)
	edges = append(edges, e)
	edges = append(edges, tail.Edges...)
	if len(edges) == 0 || len(edges) > maxHops {
		return Path{}, false
	}
	var cost float64
	for _, x := range edges {
		cost += edgeCost(x.Type)
	}
	return Path{Nodes: nodes, Edges: edges, Cost: cost}, true
}

// collapseByRoute keeps one representative per distinct route.
//
// Routes that differ only in which member of a group starts them are one
// finding with one fix. Printing five of them buries the other findings and
// reads, to a client, as padding. The cheapest representative is kept and the
// rest are counted, so the blast radius is still reported — as a number, in one
// row, which is what someone scheduling the work needs.
func collapseByRoute(ps []Path) []Path {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Cost != ps[j].Cost {
			return ps[i].Cost < ps[j].Cost
		}
		return ps[i].Key() < ps[j].Key()
	})
	byRoute := map[string]int{} // signature -> index into out
	starts := map[string]map[string]bool{}
	var out []Path
	for _, p := range ps {
		sig := p.routeSignature()
		idx, ok := byRoute[sig]
		if !ok {
			byRoute[sig] = len(out)
			starts[sig] = map[string]bool{}
			if len(p.Nodes) > 0 {
				starts[sig][p.Nodes[0]] = true
			}
			p.StartCount = 1
			out = append(out, p)
			continue
		}
		if len(p.Nodes) > 0 && !starts[sig][p.Nodes[0]] {
			starts[sig][p.Nodes[0]] = true
			out[idx].StartCount++
		}
	}
	return out
}

// routeSignature identifies a route by the part of it that has to be fixed.
// The leading membership hops carry the starting principal into the group that
// actually holds the permission; every member of that group produces the same
// route and the same remediation, so they are not part of the identity.
func (p Path) routeSignature() string {
	i := 0
	for i < len(p.Edges)-1 && p.Edges[i].Type == parse.MemberOf {
		i++
	}
	var b strings.Builder
	for _, e := range p.Edges[i:] {
		b.WriteString(e.From)
		b.WriteByte('-')
		b.WriteString(string(e.Type))
		b.WriteString("->")
		b.WriteString(e.To)
		b.WriteByte(';')
	}
	return b.String()
}

func reconstructForward(forward map[string]parse.Edge, start, crown string, maxHops int) (Path, bool) {
	var nodes []string
	var edges []parse.Edge
	cur := start
	nodes = append(nodes, cur)
	var cost float64
	for cur != crown {
		e, ok := forward[cur]
		if !ok {
			return Path{}, false
		}
		edges = append(edges, e)
		cost += edgeCost(e.Type)
		nodes = append(nodes, e.To)
		cur = e.To
		if len(edges) > maxHops {
			return Path{}, false
		}
	}
	return Path{Nodes: nodes, Edges: edges, Cost: cost}, true
}

// dijkstra finds the cheapest path from any low-priv start to target (forward,
// via a virtual super-source). Used for non-crown HVTs.
func (f *finder) dijkstra(target string) (Path, bool) {
	dist := map[string]float64{superSource: 0}
	prev := map[string]parse.Edge{}
	hops := map[string]int{superSource: 0}
	pq := &pqueue{{node: superSource, dist: 0}}
	heap.Init(pq)

	for pq.Len() > 0 {
		cur := heap.Pop(pq).(pqItem)
		if cur.dist > dist[cur.node] {
			continue
		}
		if cur.node == target {
			return reconstructBack(prev, target), true
		}
		if hops[cur.node] >= f.maxHops {
			continue
		}
		for _, st := range f.neighbors(cur.node) {
			nd := cur.dist + st.cost
			if old, ok := dist[st.to]; !ok || nd < old {
				dist[st.to] = nd
				prev[st.to] = st.edge
				hops[st.to] = hops[cur.node] + 1
				heap.Push(pq, pqItem{node: st.to, dist: nd})
			}
		}
	}
	return Path{}, false
}

func (f *finder) neighbors(node string) []step {
	if node == superSource {
		out := make([]step, 0, len(f.starts))
		for _, s := range f.starts {
			out = append(out, step{to: s, cost: 0, edge: parse.Edge{From: superSource, To: s, Type: "start"}})
		}
		return out
	}
	var out []step
	for _, e := range f.g.Out(node) {
		out = append(out, step{to: e.To, cost: edgeCost(e.Type), edge: e})
	}
	return out
}

func reconstructBack(prev map[string]parse.Edge, target string) Path {
	var nodes []string
	var edges []parse.Edge
	cur := target
	var cost float64
	for {
		nodes = append(nodes, cur)
		e, ok := prev[cur]
		if !ok {
			break
		}
		if e.Type != "start" {
			edges = append(edges, e)
			cost += edgeCost(e.Type)
		}
		cur = e.From
		if cur == superSource {
			break
		}
	}
	for i, j := 0, len(nodes)-1; i < j; i, j = i+1, j-1 {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}
	for i, j := 0, len(edges)-1; i < j; i, j = i+1, j-1 {
		edges[i], edges[j] = edges[j], edges[i]
	}
	return Path{Nodes: nodes, Edges: edges, Cost: cost}
}

func edgeCost(t parse.EdgeType) float64 {
	s := t.Profile().Success
	if s <= 0 {
		s = 1e-3
	}
	return -math.Log(s)
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// ---- priority queue ----

type step struct {
	to   string
	cost float64
	edge parse.Edge
}

type pqItem struct {
	node string
	dist float64
}

type pqueue []pqItem

func (p pqueue) Len() int           { return len(p) }
func (p pqueue) Less(i, j int) bool { return p[i].dist < p[j].dist }
func (p pqueue) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p *pqueue) Push(x any)        { *p = append(*p, x.(pqItem)) }
func (p *pqueue) Pop() any {
	old := *p
	n := len(old)
	it := old[n-1]
	*p = old[:n-1]
	return it
}
