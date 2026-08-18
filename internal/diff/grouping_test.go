package diff_test

import (
	"context"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/diff"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/pathfind"
	"github.com/harbingerlabs/harbinger-cli/internal/score"
)

func compare(t *testing.T, g0, g1 *parse.Graph) *diff.Result {
	t.Helper()
	d, err := diff.Compare(context.Background(), g0, g1, &parse.Report{}, &parse.Report{},
		nil, "", pathfind.Default(), score.Distilled{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A granted DCSync reaches the domain object, not the Domain Admins group.
// Reporting only crown routes dropped it from the diff entirely — the analysis
// ranked it first and the second run never mentioned it.
func TestNewDCSyncGrantAppearsInTheDiff(t *testing.T) {
	g0, g1 := base(), base()
	g0.AddNode(&parse.Node{ID: dom, Kind: parse.KindDomain, Name: "CORP.LOCAL", DomainSID: dom})
	g1.AddNode(&parse.Node{ID: dom, Kind: parse.KindDomain, Name: "CORP.LOCAL", DomainSID: dom})
	g1.AddNode(&parse.Node{ID: sid(1500), Kind: parse.KindUser, Name: "svc-scanner", DomainSID: dom, Enabled: true})
	g0.AddNode(&parse.Node{ID: sid(1500), Kind: parse.KindUser, Name: "svc-scanner", DomainSID: dom, Enabled: true})
	g1.AddEdge(sid(1500), dom, parse.DCSync, true)

	d := compare(t, g0, g1)
	var found bool
	for _, c := range d.OpenedBy {
		if c.Step.Edge == parse.DCSync && c.Step.FromName == "svc-scanner" {
			found = true
			if !c.Structural {
				t.Error("a granted replication right was classified as an observation")
			}
		}
	}
	if !found {
		t.Fatal("the new DCSync grant does not appear among the changes that opened routes")
	}
}

// One administrator signing in to a different machine opens a route from every
// principal who can reach it. Those are one event, and reporting them as N
// findings pushes the real changes off the end of the list.
func TestOneSessionMoveIsOneChange(t *testing.T) {
	g0, g1 := base(), base()
	for _, g := range []*parse.Graph{g0, g1} {
		// Three principals who can all take over the workstation.
		for _, rid := range []int{2001, 2002, 2003} {
			g.AddNode(&parse.Node{ID: sid(rid), Kind: parse.KindUser, Name: "hd", DomainSID: dom, Enabled: true})
			g.AddEdge(sid(rid), sid(1201), parse.MemberOf, false)
		}
		g.AddEdge(sid(1201), sid(1302), parse.AdminTo, false)
		g.AddNode(&parse.Node{ID: sid(1302), Kind: parse.KindComputer, Name: "wks-02", DomainSID: dom, Enabled: true})
	}
	// The admin's session moved to the second machine.
	g1.AddEdge(sid(1302), sid(1111), parse.HasSession, false)

	d := compare(t, g0, g1)
	if len(d.OpenedBy) != 1 {
		t.Fatalf("one session move should be one change, got %d", len(d.OpenedBy))
	}
	c := d.OpenedBy[0]
	if c.Structural {
		t.Error("a session was classified as a configuration change")
	}
	if c.Routes < 1 {
		t.Error("the change does not record how many routes it opened")
	}
}

// Structural changes must outrank observational ones however much risk the
// churn carries, or a granted permission is buried under session noise.
func TestGrantedPermissionsSortAboveSessionChurn(t *testing.T) {
	g0, g1 := base(), base()
	for _, g := range []*parse.Graph{g0, g1} {
		g.AddNode(&parse.Node{ID: dom, Kind: parse.KindDomain, Name: "CORP.LOCAL", DomainSID: dom})
		g.AddNode(&parse.Node{ID: sid(1500), Kind: parse.KindUser, Name: "svc-scanner", DomainSID: dom, Enabled: true})
		g.AddNode(&parse.Node{ID: sid(1302), Kind: parse.KindComputer, Name: "wks-02", DomainSID: dom, Enabled: true})
		g.AddEdge(sid(1201), sid(1302), parse.AdminTo, false)
	}
	g1.AddEdge(sid(1500), dom, parse.DCSync, true)            // structural
	g1.AddEdge(sid(1302), sid(1111), parse.HasSession, false) // churn

	d := compare(t, g0, g1)
	if len(d.OpenedBy) < 2 {
		t.Fatalf("expected both changes, got %d", len(d.OpenedBy))
	}
	if !d.OpenedBy[0].Structural {
		t.Errorf("session churn outranked a granted permission: first change is %s",
			d.OpenedBy[0].Step.Edge)
	}
}
