package diff_test

import (
	"context"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/diff"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/pathfind"
	"github.com/harbingerlabs/harbinger-cli/internal/score"
)

const dom = "S-1-5-21-9-9-9"

func sid(rid int) string { return dom + "-" + itoa(rid) }
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// base builds the shared part of both snapshots: jon -> Night's Watch, eddard ->
// DA, and Winterfell has eddard's session. Crown = Domain Admins (RID 512).
func base() *parse.Graph {
	g := parse.NewGraph()
	g.AddNode(&parse.Node{ID: sid(1105), Kind: parse.KindUser, Name: "jon", DomainSID: dom, Enabled: true})
	g.AddNode(&parse.Node{ID: sid(1111), Kind: parse.KindUser, Name: "eddard", DomainSID: dom, Enabled: true})
	g.AddNode(&parse.Node{ID: sid(512), Kind: parse.KindGroup, Name: "Domain Admins", DomainSID: dom})
	g.AddNode(&parse.Node{ID: sid(1201), Kind: parse.KindGroup, Name: "Nights Watch", DomainSID: dom})
	g.AddNode(&parse.Node{ID: sid(1301), Kind: parse.KindComputer, Name: "winterfell", DomainSID: dom, Enabled: true})

	g.AddEdge(sid(1105), sid(1201), parse.MemberOf, false)
	g.AddEdge(sid(1111), sid(512), parse.MemberOf, false)
	g.AddEdge(sid(1301), sid(1111), parse.HasSession, false)
	return g
}

func TestDiffFlagsOpenedPath(t *testing.T) {
	g0 := base() // jon cannot reach DA (no control of winterfell)
	g1 := base()
	// The change under test: Night's Watch gains GenericAll over Winterfell.
	g1.AddEdge(sid(1201), sid(1301), parse.GenericAll, true)

	d, err := diff.Compare(context.Background(), g0, g1, &parse.Report{}, &parse.Report{}, nil, "", pathfind.Default(), score.Distilled{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if d.AddedEdges != 1 {
		t.Errorf("added edges: want 1 got %d", d.AddedEdges)
	}
	if len(d.Opened) == 0 {
		t.Fatal("diff did not flag any opened path")
	}

	// Exactly the GenericAll edge should be named as responsible.
	var responsible bool
	for _, op := range d.Opened {
		for _, e := range op.ResponsibleEdges {
			if e.Edge == parse.GenericAll && e.FromName == "Nights Watch" && e.ToName == "winterfell" {
				responsible = true
			}
		}
	}
	if !responsible {
		t.Error("the GenericAll edge was not identified as the path-opening change")
	}
}

func TestDiffNoChangeNoOpen(t *testing.T) {
	g := base()
	d, err := diff.Compare(context.Background(), base(), g, &parse.Report{}, &parse.Report{}, nil, "", pathfind.Default(), score.Distilled{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Opened) != 0 {
		t.Errorf("identical snapshots should open nothing, got %d", len(d.Opened))
	}
}
