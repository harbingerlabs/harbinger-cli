package pathfind_test

import (
	"strings"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/hvt"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/pathfind"
)

const d = "S-1-5-21-9-9-9"

// twoRoutes builds a directory where one helpdesk group reaches Domain Admins
// two structurally different ways: through a workstation (cheap) and through a
// server (dearer). Both need a different fix, so both have to be reported.
//
// Three helpdesk members share the group, so the same route is reachable from
// three principals — one finding, not three.
func twoRoutes() *parse.Graph {
	g := parse.NewGraph()
	add := func(id, name string, k parse.Kind) {
		g.AddNode(&parse.Node{ID: id, Kind: k, Name: name, Enabled: true})
	}
	add(d, "CORP.LOCAL", parse.KindDomain)
	add(d+"-512", "DOMAIN ADMINS@CORP.LOCAL", parse.KindGroup)
	add(d+"-1001", "DA.ADMIN@CORP.LOCAL", parse.KindUser)
	add(d+"-2000", "HELPDESK@CORP.LOCAL", parse.KindGroup)
	add(d+"-2001", "HD.ONE@CORP.LOCAL", parse.KindUser)
	add(d+"-2002", "HD.TWO@CORP.LOCAL", parse.KindUser)
	add(d+"-2003", "HD.THREE@CORP.LOCAL", parse.KindUser)
	add(d+"-3001", "WKS-01.CORP.LOCAL", parse.KindComputer)
	add(d+"-3002", "SRV-PRINT.CORP.LOCAL", parse.KindComputer)

	g.AddEdge(d+"-1001", d+"-512", parse.MemberOf, false)
	for _, u := range []string{"-2001", "-2002", "-2003"} {
		g.AddEdge(d+u, d+"-2000", parse.MemberOf, false)
	}
	// Route A: helpdesk -> workstation -> the admin's session.
	g.AddEdge(d+"-2000", d+"-3001", parse.AdminTo, false)
	g.AddEdge(d+"-3001", d+"-1001", parse.HasSession, false)
	// Route B: helpdesk -> print server -> the same admin's session.
	g.AddEdge(d+"-2000", d+"-3002", parse.AdminTo, false)
	g.AddEdge(d+"-3002", d+"-1001", parse.HasSession, false)
	return g
}

func routes(t *testing.T) []pathfind.Path {
	t.Helper()
	g := twoRoutes()
	return pathfind.Find(g, hvt.Resolve(g, nil), pathfind.Default())
}

// The per-principal search returns each principal's single cheapest route, so a
// second, structurally different way in is never generated. It needs a
// different remediation, so missing it means the fix list is incomplete.
func TestStructurallyDistinctRoutesAreBothFound(t *testing.T) {
	var viaWks, viaSrv bool
	for _, p := range routes(t) {
		chain := strings.Join(p.Nodes, ">")
		if strings.Contains(chain, d+"-3001") {
			viaWks = true
		}
		if strings.Contains(chain, d+"-3002") {
			viaSrv = true
		}
	}
	if !viaWks {
		t.Error("the route through the workstation was not found")
	}
	if !viaSrv {
		t.Error("the second route, through the print server, was not found — " +
			"only the cheapest route per principal was reported")
	}
}

// Every member of the group that holds the permission produces an identical
// route with an identical fix. Reporting one per member buries the other
// findings; the blast radius survives as a count.
func TestOneRoutePerFindingNotPerPrincipal(t *testing.T) {
	byRoute := map[string]int{}
	for _, p := range routes(t) {
		if len(p.Edges) == 0 {
			continue
		}
		// Identify a route by its non-membership tail.
		var key []string
		for _, e := range p.Edges {
			if e.Type != parse.MemberOf {
				key = append(key, e.From+"-"+string(e.Type)+"->"+e.To)
			}
		}
		byRoute[strings.Join(key, ";")]++
	}
	for route, n := range byRoute {
		if n > 1 {
			t.Errorf("route reported %d times, once per principal: %s", n, route)
		}
	}
	var counted bool
	for _, p := range routes(t) {
		if p.StartCount == 3 {
			counted = true
		}
	}
	if !counted {
		t.Error("no route recorded that 3 principals can walk it — the blast radius was lost")
	}
}

// Splicing two independently-computed halves can revisit a node. A route that
// passes through the same principal twice is not one anybody can walk.
func TestRoutesAreSimplePaths(t *testing.T) {
	for _, p := range routes(t) {
		seen := map[string]bool{}
		for _, n := range p.Nodes {
			if seen[n] {
				t.Errorf("route visits %s twice: %s", n, strings.Join(p.Nodes, " -> "))
			}
			seen[n] = true
		}
	}
}
