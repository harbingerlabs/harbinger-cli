package parse_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/synth"
)

func TestIngestSynth(t *testing.T) {
	dir := t.TempDir()
	if err := synth.WriteDir(dir, 0); err != nil {
		t.Fatal(err)
	}
	g, rep, err := parse.Ingest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Counts[parse.KindUser]; got != 4 {
		t.Errorf("users: want 4 got %d", got)
	}
	if got := rep.Counts[parse.KindGroup]; got != 2 {
		t.Errorf("groups: want 2 got %d", got)
	}
	if got := rep.Counts[parse.KindDomain]; got != 1 {
		t.Errorf("domains: want 1 got %d", got)
	}

	// DCSync must be synthesized from GetChanges + GetChangesAll.
	var hasDCSync bool
	for _, e := range g.Edges {
		if e.Type == parse.DCSync {
			hasDCSync = true
		}
	}
	if !hasDCSync {
		t.Error("expected synthesized DCSync edge")
	}
}

func TestIngestToleratesMalformed(t *testing.T) {
	dir := t.TempDir()
	// A junk file plus a valid one: junk should not abort the load.
	if err := os.WriteFile(filepath.Join(dir, "junk.json"), []byte("not json {{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := synth.WriteDir(dir, 0); err != nil {
		t.Fatal(err)
	}
	g, rep, err := parse.Ingest(dir)
	if err != nil {
		t.Fatalf("junk file aborted load: %v", err)
	}
	if len(g.Nodes) == 0 {
		t.Error("no nodes parsed despite valid files present")
	}
	if len(rep.Warnings) == 0 {
		t.Error("expected a warning for the malformed file")
	}
}

func TestIngestEmptyInput(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := parse.Ingest(dir); err == nil {
		t.Error("expected error on empty directory")
	}
}
