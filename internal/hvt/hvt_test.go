package hvt_test

import (
	"strings"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/hvt"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

// An MSP machine holds many clients' directories. The tool must never quietly
// pick one, merge two, or report on the wrong one.

const (
	domA = "S-1-5-21-1111-1111-1111"
	domB = "S-1-5-21-2222-2222-2222"
)

// twoTenants builds a graph holding two unrelated client directories, with A
// deliberately larger than B.
func twoTenants() *parse.Graph {
	g := parse.NewGraph()
	add := func(id string, kind parse.Kind, name string) {
		g.AddNode(&parse.Node{ID: id, Kind: kind, Name: name, Enabled: true})
	}
	add(domA, parse.KindDomain, "ALPHA.LOCAL")
	add(domA+"-512", parse.KindGroup, "DOMAIN ADMINS@ALPHA.LOCAL")
	add(domA+"-1105", parse.KindUser, "AUSER@ALPHA.LOCAL")
	add(domA+"-1106", parse.KindUser, "AUSER2@ALPHA.LOCAL")
	g.AddEdge(domA+"-1105", domA+"-512", parse.GenericAll, true)

	add(domB, parse.KindDomain, "BRAVO.LOCAL")
	add(domB+"-512", parse.KindGroup, "DOMAIN ADMINS@BRAVO.LOCAL")
	add(domB+"-1105", parse.KindUser, "BUSER@BRAVO.LOCAL")
	g.AddEdge(domB+"-1105", domB+"-512", parse.GenericAll, true)
	return g
}

func TestDetectsEveryDomain(t *testing.T) {
	r := hvt.Resolve(twoTenants(), nil)
	if len(r.Domains) != 2 {
		t.Fatalf("found %d domains, want 2: %+v", len(r.Domains), r.Domains)
	}
	// Largest first, so the default crown is not an accident of map order.
	if r.Domains[0].SID != domA {
		t.Errorf("largest domain = %s, want %s", r.Domains[0].SID, domA)
	}
	if r.Domains[0].Name != "ALPHA.LOCAL" {
		t.Errorf("domain name = %q", r.Domains[0].Name)
	}
	if r.Domains[0].Crown != domA+"-512" {
		t.Errorf("crown of ALPHA = %s", r.Domains[0].Crown)
	}
	if r.Crown != domA+"-512" {
		t.Errorf("default crown = %s, want ALPHA's Domain Admins", r.Crown)
	}
}

func TestScopeToOneTenant(t *testing.T) {
	for _, sel := range []string{domB, "BRAVO.LOCAL", "bravo.local", "bravo"} {
		r, err := hvt.ResolveScoped(twoTenants(), nil, sel)
		if err != nil {
			t.Fatalf("%q: %v", sel, err)
		}
		if r.Scope != domB {
			t.Errorf("%q: scope = %s, want %s", sel, r.Scope, domB)
		}
		if r.Crown != domB+"-512" {
			t.Errorf("%q: crown = %s, want BRAVO's Domain Admins", sel, r.Crown)
		}
		// The other tenant's Tier Zero must not be an objective in this run.
		for _, id := range r.Targets {
			if strings.HasPrefix(id, domA) {
				t.Errorf("%q: target %s leaked in from the other tenant", sel, id)
			}
		}
	}
}

func TestUnknownDomainIsRefusedWithTheList(t *testing.T) {
	_, err := hvt.ResolveScoped(twoTenants(), nil, "CHARLIE.LOCAL")
	if err == nil {
		t.Fatal("expected an error for a domain not in the export")
	}
	// The message must tell the operator what IS available.
	msg := err.Error()
	if !strings.Contains(msg, "ALPHA.LOCAL") || !strings.Contains(msg, "BRAVO.LOCAL") {
		t.Errorf("error should list the domains present, got: %s", msg)
	}
}

// Determinism matters commercially: two runs of the same export must produce
// the same report, or nobody can trust a diff.
func TestResolveIsDeterministic(t *testing.T) {
	first := hvt.Resolve(twoTenants(), nil)
	for i := 0; i < 25; i++ {
		r := hvt.Resolve(twoTenants(), nil)
		if r.Crown != first.Crown {
			t.Fatalf("run %d: crown changed %s -> %s", i, first.Crown, r.Crown)
		}
		if len(r.Targets) != len(first.Targets) {
			t.Fatalf("run %d: target count changed", i)
		}
		for j := range r.Targets {
			if r.Targets[j] != first.Targets[j] {
				t.Fatalf("run %d: target order changed at %d: %s != %s", i, j, r.Targets[j], first.Targets[j])
			}
		}
		if len(r.Domains) != len(first.Domains) || r.Domains[0].SID != first.Domains[0].SID {
			t.Fatalf("run %d: domain ordering changed", i)
		}
	}
}

func TestSingleDomainStillWorks(t *testing.T) {
	g := parse.NewGraph()
	g.AddNode(&parse.Node{ID: domA, Kind: parse.KindDomain, Name: "ALPHA.LOCAL"})
	g.AddNode(&parse.Node{ID: domA + "-512", Kind: parse.KindGroup, Name: "DOMAIN ADMINS@ALPHA.LOCAL"})
	r := hvt.Resolve(g, nil)
	if len(r.Domains) != 1 {
		t.Fatalf("want 1 domain, got %d", len(r.Domains))
	}
	if r.Crown != domA+"-512" {
		t.Errorf("crown = %s", r.Crown)
	}
}

// No domain object at all (a partial export) must still yield a reproducible
// objective rather than a random one.
func TestNoDomainObjectFallsBackDeterministically(t *testing.T) {
	g := parse.NewGraph()
	g.AddNode(&parse.Node{ID: "S-1-5-32-544", Kind: parse.KindGroup, Name: "ADMINISTRATORS@BUILTIN"})
	g.AddNode(&parse.Node{ID: "S-1-5-32-551", Kind: parse.KindGroup, Name: "BACKUP OPERATORS@BUILTIN"})
	first := hvt.Resolve(g, nil).Crown
	if first == "" {
		t.Fatal("no crown chosen")
	}
	for i := 0; i < 20; i++ {
		if got := hvt.Resolve(g, nil).Crown; got != first {
			t.Fatalf("crown not stable: %s vs %s", got, first)
		}
	}
}

func TestDomainSIDOf(t *testing.T) {
	if got := hvt.DomainSIDOf(domA + "-1105"); got != domA {
		t.Errorf("principal SID -> %q, want %q", got, domA)
	}
	if got := hvt.DomainSIDOf(domA); got != domA {
		t.Errorf("bare domain SID -> %q, want %q", got, domA)
	}
	if got := hvt.DomainSIDOf("S-1-5-32-544"); got != "" {
		t.Errorf("built-in SID -> %q, want empty", got)
	}
}
