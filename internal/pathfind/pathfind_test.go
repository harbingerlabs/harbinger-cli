package pathfind_test

import (
	"strings"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/hvt"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/pathfind"
	"github.com/harbingerlabs/harbinger-cli/internal/synth"
)

func load(t *testing.T) (*parse.Graph, *hvt.Resolved) {
	t.Helper()
	dir := t.TempDir()
	if err := synth.WriteDir(dir, 0); err != nil {
		t.Fatal(err)
	}
	g, _, err := parse.Ingest(dir)
	if err != nil {
		t.Fatal(err)
	}
	return g, hvt.Resolve(g, nil)
}

func TestFindsCrownAndMultiHop(t *testing.T) {
	g, res := load(t)
	paths := pathfind.Find(g, res, pathfind.Default())
	if len(paths) < 1 {
		t.Fatalf("want >=1 path, got %d", len(paths))
	}

	var foundMultiHop bool
	for _, p := range paths {
		if p.Target() == res.Crown && len(p.Edges) == 4 {
			foundMultiHop = true
		}
	}
	if !foundMultiHop {
		t.Error("missing the 4-hop jon.snow -> ... -> Domain Admins path")
	}
}

// An administrator's own group membership is not an escalation route, and it is
// the shortest path to the crown in every real directory. Reporting it puts a
// non-finding at the top of the ranking, above the genuine one, which is the
// most expensive kind of wrong output this tool can produce.
//
// eddard.stark is a member of Domain Admins in the fixture.
func TestExistingAdminIsNotAStartingPoint(t *testing.T) {
	g, res := load(t)
	for _, p := range pathfind.Find(g, res, pathfind.Default()) {
		if len(p.Nodes) == 0 {
			continue
		}
		start := g.Node(p.Nodes[0])
		if start == nil {
			continue
		}
		if strings.HasPrefix(start.Name, "EDDARD.STARK") {
			t.Errorf("a Domain Admin was used as a starting principal: %s -> %s",
				start.Name, strings.Join(p.Nodes, " -> "))
		}
		if res.TierZero[p.Nodes[0]] {
			t.Errorf("path starts from a Tier Zero principal: %s", strings.Join(p.Nodes, " -> "))
		}
	}
}

// The membership closure must be transitive: a member of a group nested inside
// Domain Admins is just as much an administrator as a direct member.
func TestTierZeroMembershipIsTransitive(t *testing.T) {
	g, res := load(t)
	da := res.Crown
	if da == "" {
		t.Fatal("no crown resolved")
	}
	for _, e := range g.In(da) {
		if e.Type != parse.MemberOf {
			continue
		}
		if !res.TierZero[e.From] {
			n := g.Node(e.From)
			name := e.From
			if n != nil {
				name = n.Name
			}
			t.Errorf("%s is a member of the crown group but is not Tier Zero", name)
		}
	}
}

func TestPathsAreValidChains(t *testing.T) {
	g, res := load(t)
	for _, p := range pathfind.Find(g, res, pathfind.Default()) {
		if len(p.Nodes) != len(p.Edges)+1 {
			t.Fatalf("node/edge count mismatch: %d nodes, %d edges", len(p.Nodes), len(p.Edges))
		}
		for i, e := range p.Edges {
			if e.From != p.Nodes[i] || e.To != p.Nodes[i+1] {
				t.Fatalf("edge %d does not connect nodes %s -> %s", i, p.Nodes[i], p.Nodes[i+1])
			}
		}
	}
}

func TestDeterministicOrder(t *testing.T) {
	g, res := load(t)
	first := pathfind.Find(g, res, pathfind.Default())
	for i := 0; i < 5; i++ {
		again := pathfind.Find(g, res, pathfind.Default())
		if len(again) != len(first) {
			t.Fatalf("nondeterministic path count: %d vs %d", len(again), len(first))
		}
		for j := range first {
			if strings.Join(first[j].Nodes, ">") != strings.Join(again[j].Nodes, ">") {
				t.Fatalf("nondeterministic ordering at %d", j)
			}
		}
	}
}
