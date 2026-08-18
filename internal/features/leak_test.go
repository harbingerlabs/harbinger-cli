package features_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/features"
	"github.com/harbingerlabs/harbinger-cli/internal/hvt"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/pathfind"
	"github.com/harbingerlabs/harbinger-cli/internal/synth"
)

// TestNoIdentityLeak is the single most important test in the client: it proves
// that the outbound payload contains no identity-bearing string from the graph.
// If this ever fails, the entire privacy promise is broken.
func TestNoIdentityLeak(t *testing.T) {
	dir := t.TempDir()
	if err := synth.WriteDir(dir, 40); err != nil {
		t.Fatal(err)
	}
	g, _, err := parse.Ingest(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := hvt.Resolve(g, nil)
	paths := pathfind.Find(g, res, pathfind.Default())
	if len(paths) == 0 {
		t.Fatal("no paths — cannot test payload")
	}
	req, _ := features.Extract(g, paths, "test")

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.ToLower(string(raw))

	for id, n := range g.Nodes {
		if id != "" && strings.Contains(payload, strings.ToLower(id)) {
			t.Errorf("SID leaked into payload: %q", id)
		}
		if n.Name != "" && strings.Contains(payload, strings.ToLower(n.Name)) {
			t.Errorf("name leaked into payload: %q", n.Name)
		}
		if n.DomainSID != "" && strings.Contains(payload, strings.ToLower(n.DomainSID)) {
			t.Errorf("domain SID leaked into payload: %q", n.DomainSID)
		}
	}

	// Structural sanity: the payload must contain tokens and edge types.
	if !strings.Contains(payload, "n_") {
		t.Error("payload has no node tokens")
	}
	if !strings.Contains(payload, "memberof") {
		t.Error("payload has no edge-type features")
	}
}

// TestTokensAreStableWithinRunUniqueAcrossRuns checks token hygiene.
func TestTokensAreStableWithinRunUniqueAcrossRuns(t *testing.T) {
	tk := features.NewTokenizer()
	a1 := tk.Node("S-1-5-21-x-500")
	a2 := tk.Node("S-1-5-21-x-500")
	if a1 != a2 {
		t.Errorf("token not stable within a run: %s != %s", a1, a2)
	}
	if r, ok := tk.Real(a1); !ok || r != "S-1-5-21-x-500" {
		t.Errorf("reverse map broken: %q %v", r, ok)
	}
	tk2 := features.NewTokenizer()
	if tk.RunToken == tk2.RunToken {
		t.Error("run tokens collided across runs")
	}
}
