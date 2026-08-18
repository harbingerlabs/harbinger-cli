package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/analyze"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

// The JSON output is what MSPs wire into ticketing and RMM systems. Untagged
// structs make the key names an accident of the Go field names, so an internal
// rename silently breaks every integration. These are the names we promise.
func TestAnalysisJSONKeysAreTheDocumentedOnes(t *testing.T) {
	r := &analyze.Result{
		CrownName: "DOMAIN ADMINS@CORP.LOCAL",
		Paths: []analyze.ScoredPath{{
			Rank: 1, TargetName: "DOMAIN ADMINS@CORP.LOCAL", Risk: 0.5,
			BlindSpot: true, StartCount: 3,
			Steps: []analyze.Step{{FromName: "A", ToName: "B", Edge: parse.GenericAll}},
		}},
		TopFix: &analyze.Fix{Edge: parse.GenericAll, FromName: "A", ToName: "B"},
	}
	var b bytes.Buffer
	if err := JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["schema"] != SchemaAnalysis {
		t.Errorf("schema = %v, want %s", got["schema"], SchemaAnalysis)
	}
	res, ok := got["result"].(map[string]any)
	if !ok {
		t.Fatal("no result object")
	}
	for _, k := range []string{"crown_name", "paths", "top_fix", "scorer", "domains"} {
		if _, ok := res[k]; !ok {
			t.Errorf("result is missing the documented key %q", k)
		}
	}
	paths, _ := res["paths"].([]any)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	p, _ := paths[0].(map[string]any)
	for _, k := range []string{"rank", "risk", "hops", "evasion", "blind_spot", "start_count", "steps", "target_name"} {
		if _, ok := p[k]; !ok {
			t.Errorf("path is missing the documented key %q", k)
		}
	}
	steps, _ := p["steps"].([]any)
	st, _ := steps[0].(map[string]any)
	for _, k := range []string{"from_name", "to_name", "edge"} {
		if _, ok := st[k]; !ok {
			t.Errorf("step is missing the documented key %q", k)
		}
	}
}

// A route nobody can walk is not a route: the count is at least one.
func TestStartCountIsNeverZeroInOutput(t *testing.T) {
	r := &analyze.Result{Paths: []analyze.ScoredPath{{Rank: 1, StartCount: 3}}}
	var b bytes.Buffer
	if err := JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b.Bytes(), []byte(`"start_count": 3`)) {
		t.Error("start_count did not survive serialization")
	}
}
