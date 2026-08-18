package load

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/adexplorer"
)

// writeSnapshot puts a real AD Explorer snapshot at path.
func writeSnapshot(t *testing.T, path string) {
	t.Helper()
	if err := adexplorer.SynthWriteFile(path); err != nil {
		t.Fatalf("write synthetic snapshot: %v", err)
	}
}

// An MSP folder with two clients' snapshots in it must not be resolved by
// guessing. Picking one silently is how a report reaches the wrong customer.
func TestFolderWithTwoSnapshotsIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeSnapshot(t, filepath.Join(dir, "acme.dat"))
	writeSnapshot(t, filepath.Join(dir, "globex.dat"))

	_, _, err := Any(dir)
	if err == nil {
		t.Fatal("two snapshots in one folder were resolved silently; expected a refusal")
	}
	msg := err.Error()
	for _, want := range []string{"acme.dat", "globex.dat"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not name %q, so the operator cannot pick one:\n%s", want, msg)
		}
	}
}

// One snapshot in a folder still works, and the report names the file it read
// rather than the folder the operator typed.
func TestFolderWithOneSnapshotNamesTheFile(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "acme.dat")
	writeSnapshot(t, snap)

	_, rep, err := Any(dir)
	if err != nil {
		t.Fatalf("single-snapshot folder failed to load: %v", err)
	}
	if rep.Input != snap {
		t.Errorf("report input = %q, want the resolved snapshot %q", rep.Input, snap)
	}
}

// A file passed directly is stamped as itself, so every report is traceable to
// the export it came from.
func TestDirectFileIsStamped(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "client.dat")
	writeSnapshot(t, snap)

	_, rep, err := Any(snap)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if rep.Input != snap {
		t.Errorf("report input = %q, want %q", rep.Input, snap)
	}
}

func TestEmptyAndMissingInputsFailCleanly(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.dat")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Any(empty); err == nil {
		t.Error("empty file was accepted")
	}
	if _, _, err := Any(filepath.Join(dir, "nope.dat")); err == nil {
		t.Error("missing file was accepted")
	}
}
