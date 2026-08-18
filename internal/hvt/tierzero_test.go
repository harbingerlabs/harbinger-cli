package hvt_test

import (
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/hvt"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

const dom = "S-1-5-21-1-2-3"

func graph() *parse.Graph {
	g := parse.NewGraph()
	g.AddNode(&parse.Node{ID: dom, Kind: parse.KindDomain, Name: "CORP.LOCAL"})
	g.AddNode(&parse.Node{ID: dom + "-512", Kind: parse.KindGroup, Name: "DOMAIN ADMINS@CORP.LOCAL"})
	g.AddNode(&parse.Node{ID: dom + "-1101", Kind: parse.KindUser, Name: "ADMIN.ALICE@CORP.LOCAL", Enabled: true})
	g.AddNode(&parse.Node{ID: dom + "-1102", Kind: parse.KindUser, Name: "STAFF.BOB@CORP.LOCAL", Enabled: true})
	g.AddNode(&parse.Node{ID: dom + "-1200", Kind: parse.KindGroup, Name: "NESTED-ADMINS@CORP.LOCAL"})
	g.AddNode(&parse.Node{ID: dom + "-1103", Kind: parse.KindUser, Name: "NESTED.CARL@CORP.LOCAL", Enabled: true})

	g.AddEdge(dom+"-1101", dom+"-512", parse.MemberOf, false)  // direct admin
	g.AddEdge(dom+"-1200", dom+"-512", parse.MemberOf, false)  // nested group
	g.AddEdge(dom+"-1103", dom+"-1200", parse.MemberOf, false) // admin via nesting
	return g
}

// Rights over the domain object are domain compromise on their own: DCSync
// extracts every credential in the directory without touching a group.
func TestDomainObjectIsTierZero(t *testing.T) {
	res := hvt.Resolve(graph(), nil)
	if !res.TierZero[dom] {
		t.Fatal("the domain object is not Tier Zero, so rights over it are not an objective")
	}
	var found bool
	for _, id := range res.Targets {
		if id == dom {
			found = true
		}
	}
	if !found {
		t.Error("the domain object is Tier Zero but not in the target list")
	}
}

// An administrator is not a low-privilege starting point, however they got the
// privilege — directly or through a nested group.
func TestAdminsAreTierZeroThroughMembership(t *testing.T) {
	res := hvt.Resolve(graph(), nil)
	for _, tc := range []struct {
		id, why string
	}{
		{dom + "-1101", "a direct member of Domain Admins"},
		{dom + "-1200", "a group nested inside Domain Admins"},
		{dom + "-1103", "a member of a group nested inside Domain Admins"},
	} {
		if !res.TierZero[tc.id] {
			t.Errorf("%s is not Tier Zero", tc.why)
		}
	}
	if res.TierZero[dom+"-1102"] {
		t.Error("an ordinary member of staff was marked Tier Zero")
	}
}

// Widening Tier Zero must not turn every administrator into an objective of
// their own; the objective list is fixed before membership is expanded.
func TestMembershipExpansionDoesNotAddTargets(t *testing.T) {
	res := hvt.Resolve(graph(), nil)
	for _, id := range res.Targets {
		if id == dom+"-1101" || id == dom+"-1103" {
			t.Errorf("an administrator became a target in their own right: %s", id)
		}
	}
}
