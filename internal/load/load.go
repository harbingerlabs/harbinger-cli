// Package load picks the right ingester for whatever the user actually has.
//
// MSPs do not arrive with a tidy BloodHound zip. They arrive with a folder, a
// .dat from AD Explorer, a zip inside a zip, or a single JSON someone emailed
// them. One command has to take all of it, so format detection is by content
// rather than by file extension.
package load

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/adexplorer"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

// Any ingests an export of any supported shape:
//   - an AD Explorer snapshot (.dat, detected by signature)
//   - a BloodHound CE or Legacy export: .zip, a directory, or a single .json
func Any(path string) (*parse.Graph, *parse.Report, error) {
	g, rep, err := ingest(path)
	// Stamp the file that was actually read, which is not always the path the
	// operator typed — a folder resolves to one snapshot inside it.
	if rep != nil && rep.Input == "" {
		rep.Input = path
	}
	return g, rep, err
}

func ingest(path string) (*parse.Graph, *parse.Report, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("no such file or folder: %q\n"+
				"  Pass the BloodHound .zip, the folder holding the .json files, or an\n"+
				"  AD Explorer .dat snapshot.", path)
		}
		return nil, nil, fmt.Errorf("cannot read %q: %w", path, err)
	}

	if fi.IsDir() {
		// A folder may hold a snapshot rather than JSON.
		snaps := findSnapshots(path)
		// An MSP keeps one folder per client, or one folder with every client in
		// it. Guessing between two clients' snapshots is how a report reaches the
		// wrong customer, so ambiguity is refused rather than resolved.
		if len(snaps) > 1 {
			return nil, nil, fmt.Errorf("%q holds %d AD Explorer snapshots, and they may be different clients:\n%s\n"+
				"  Pass the one you want by name:  harbinger analyze %s",
				path, len(snaps), bulleted(snaps), filepath.Join(path, filepath.Base(snaps[0])))
		}
		if len(snaps) == 1 {
			g, rep, err := adexplorer.Ingest(snaps[0])
			if rep != nil {
				rep.Input = snaps[0]
			}
			return g, rep, err
		}
		return parse.Ingest(path)
	}

	if fi.Size() == 0 {
		return nil, nil, fmt.Errorf("%q is empty (0 bytes) — the export or copy did not finish", path)
	}
	if adexplorer.IsSnapshot(path) {
		return adexplorer.Ingest(path)
	}
	// A .dat that is not a snapshot is a common mistake worth naming precisely.
	if strings.EqualFold(filepath.Ext(path), ".dat") {
		return nil, nil, fmt.Errorf("%q ends in .dat but does not carry the AD Explorer snapshot signature.\n"+
			"  Make sure it was produced by AD Explorer's File > Create Snapshot, and that the\n"+
			"  snapshot finished writing before the file was copied.", filepath.Base(path))
	}
	return parse.Ingest(path)
}

// findSnapshots returns every AD Explorer snapshot directly inside a directory.
// os.ReadDir sorts by filename, so the order — and therefore any message built
// from it — is the same on every run.
func findSnapshots(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if adexplorer.IsSnapshot(p) {
			found = append(found, p)
		}
	}
	return found
}

// bulleted renders paths one per line, by base name, for an error message.
func bulleted(paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&b, "    • %s\n", filepath.Base(p))
	}
	return strings.TrimRight(b.String(), "\n")
}
