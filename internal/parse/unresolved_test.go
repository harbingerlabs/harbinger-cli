package parse

import "testing"

// BloodHound writes one file per object type, and computers.json is read before
// groups.json — so an ACE on a computer refers forward to a principal that
// arrives later in the same load. Counting those as dangling reported 1,317
// "dangling refs" on a directory whose true figure was 44, which reads to an
// operator as a broken collection.
func TestForwardReferencesAreNotCountedAsGaps(t *testing.T) {
	g := NewGraph()
	// An edge naming a principal we have not seen yet.
	g.AddEdge("S-1-5-21-1-2-3-1105", "S-1-5-21-1-2-3-1200", GenericAll, true)
	if n := g.CountUnresolved(); n != 2 {
		t.Fatalf("before the records arrive, want 2 unresolved, got %d", n)
	}
	// Both records now arrive, as they would later in the load.
	g.AddNode(&Node{ID: "S-1-5-21-1-2-3-1105", Kind: KindUser, Name: "BOB"})
	g.AddNode(&Node{ID: "S-1-5-21-1-2-3-1200", Kind: KindGroup, Name: "IT"})
	if n := g.CountUnresolved(); n != 0 {
		t.Errorf("forward references still counted as gaps after the records loaded: %d", n)
	}
}

// A principal that never appears anywhere is a real gap: a permission held by
// an account deleted years ago, or one in a domain that was not collected.
func TestTrulyMissingPrincipalsAreCounted(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "S-1-5-21-1-2-3-1105", Kind: KindUser, Name: "BOB"})
	g.AddEdge("S-1-5-21-1-2-3-1105", "S-1-5-21-1-2-3-4444", GenericAll, true)
	if n := g.CountUnresolved(); n != 1 {
		t.Errorf("want 1 unresolved principal, got %d", n)
	}
}
