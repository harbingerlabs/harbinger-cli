package parse

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Report captures load diagnostics surfaced to the user (never transmitted).
type Report struct {
	Sources      []string
	Counts       map[Kind]int
	Edges        int
	Dangling     int
	UnknownEdges int
	Warnings     []string

	// Modality names how the data was collected (e.g. "SharpHound export",
	// "AD Explorer snapshot (LDAP only)").
	Modality string
	// Input is the export this report was built from, as resolved on disk. An
	// MSP runs this against several clients in a sitting; a report that does not
	// name its own source cannot be checked against the client it was sent to.
	Input string
	// Gaps names what this collection could NOT see. Rendered in every report:
	// a collection gap must never be read as a clean bill of health.
	Gaps []string
}

// Ingest reads a BloodHound/SharpHound export from a zip, a directory, or a
// single JSON file, and returns a normalized graph. It tolerates partial
// collections and unknown edges (logged, not fatal) per the robustness spec.
func Ingest(path string) (*Graph, *Report, error) {
	g := NewGraph()
	rep := &Report{Counts: map[Kind]int{}}

	docs, err := openDocs(path)
	if err != nil {
		return nil, nil, err
	}
	if len(docs) == 0 {
		// An MSP keeps one folder per client. Pointing at the parent is the
		// obvious mistake, and naming what is actually in there turns a dead end
		// into the next command.
		if subs := subdirsWithExports(path); len(subs) > 0 {
			var b strings.Builder
			for _, d := range subs {
				fmt.Fprintf(&b, "\n    • %s", d)
			}
			return nil, nil, fmt.Errorf("no export directly in %q, but %d subfolder(s) look like exports:%s\n"+
				"  Analyze one client at a time:  harbinger analyze %s",
				path, len(subs), b.String(), filepath.Join(path, subs[0]))
		}
		return nil, nil, fmt.Errorf("no BloodHound JSON found at %q (expected a .zip, a directory of *.json, or a single .json)", path)
	}
	defer closeDocs(docs)

	for _, d := range docs {
		rep.Sources = append(rep.Sources, d.name)
		if err := ingestDoc(g, d.r, rep); err != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s: %v", d.name, err))
		}
	}

	synthesizeDCSync(g)

	for k, v := range g.LoadCounts {
		rep.Counts[k] = v
	}
	rep.Edges = len(g.Edges)
	rep.Dangling = g.CountUnresolved()
	rep.Modality = "BloodHound/SharpHound export"
	rep.Gaps = detectGaps(g)
	if len(g.Nodes) == 0 {
		return nil, nil, fmt.Errorf("parsed 0 nodes — is this a BloodHound export? (%s)", strings.Join(rep.Sources, ", "))
	}
	return g, rep, nil
}

// subdirsWithExports lists immediate subdirectories that themselves hold an
// export, so a wrong path can name the right ones.
func subdirsWithExports(path string) []string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(path, e.Name())
		if m, _ := filepath.Glob(filepath.Join(sub, "*.json")); len(m) > 0 {
			out = append(out, e.Name())
			continue
		}
		if z, _ := filepath.Glob(filepath.Join(sub, "*.zip")); len(z) > 0 {
			out = append(out, e.Name())
		}
	}
	return out
}

// detectGaps names collection blind spots. A path we cannot see because a
// modality was never collected must be reported as a gap, never as safety.
func detectGaps(g *Graph) []string {
	present := map[EdgeType]bool{}
	for _, e := range g.Edges {
		present[e.Type] = true
	}
	var gaps []string
	if !present[HasSession] {
		gaps = append(gaps, "No sessions in this export — paths that start from a logged-on user's credential are invisible. Re-collect with SharpHound's Session method to close this.")
	}
	if !present[AdminTo] && !present[CanRDP] && !present[CanPSRemote] {
		gaps = append(gaps, "No local group membership in this export (AdminTo/CanRDP/CanPSRemote) — host-to-host lateral movement is invisible. Re-collect with SharpHound's LocalAdmin/RDP methods to close this.")
	}
	if g.LoadCounts[KindComputer] == 0 {
		gaps = append(gaps, "No computer objects in this export — only directory-object paths were analyzed.")
	}
	return gaps
}

type doc struct {
	name string
	r    io.Reader
	c    io.Closer
}

func closeDocs(ds []doc) {
	for _, d := range ds {
		if d.c != nil {
			_ = d.c.Close()
		}
	}
}

// openDocs resolves the input into a list of JSON readers.
func openDocs(path string) ([]doc, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", path, err)
	}
	switch {
	case fi.IsDir():
		matches, _ := filepath.Glob(filepath.Join(path, "*.json"))
		zips, _ := filepath.Glob(filepath.Join(path, "*.zip"))
		var out []doc
		for _, m := range matches {
			f, err := os.Open(m)
			if err != nil {
				continue
			}
			out = append(out, doc{name: filepath.Base(m), r: f, c: f})
		}
		for _, z := range zips {
			zd, err := openZip(z)
			if err == nil {
				out = append(out, zd...)
			}
		}
		return out, nil
	case strings.HasSuffix(strings.ToLower(path), ".zip"):
		return openZip(path)
	default:
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return []doc{{name: filepath.Base(path), r: f, c: f}}, nil
	}
}

func openZip(path string) ([]doc, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	var out []doc
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out = append(out, doc{name: filepath.Base(f.Name), r: rc, c: rc})
	}
	// Keep the zip reader alive by closing it after all entries are consumed.
	out = append(out, doc{name: "", r: strings.NewReader(""), c: zr})
	return out, nil
}

// ingestDoc reads one BloodHound file. BloodHound writes "data" BEFORE "meta",
// so we cannot learn the object kind by forward-streaming alone. We decode the
// top-level object holding "data" as a raw slice (so meta is available first),
// then stream the data array element-by-element so live object count stays at 1.
func ingestDoc(g *Graph, r io.Reader, rep *Report) error {
	var top struct {
		Meta struct {
			Type    string `json:"type"`
			Version int    `json:"version"`
		} `json:"meta"`
		Data json.RawMessage `json:"data"`
	}
	dec := json.NewDecoder(r)
	if err := dec.Decode(&top); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	kind := kindFromMeta(top.Meta.Type)
	if len(top.Data) == 0 {
		return nil
	}
	// Fall back to inferring kind from the filename/type if meta was absent by
	// leaving kind = Unknown; per-object normalization still records nodes.
	return streamData(g, top.Data, kind, rep)
}

func streamData(g *Graph, raw json.RawMessage, kind Kind, rep *Report) error {
	adec := json.NewDecoder(strings.NewReader(string(raw)))
	tok, err := adec.Token() // '['
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil // data may be null on empty collections
	}
	for adec.More() {
		var obj map[string]any
		if err := adec.Decode(&obj); err != nil {
			return err
		}
		normalizeObject(g, obj, kind, rep)
	}
	return nil
}

func kindFromMeta(t string) Kind {
	switch strings.ToLower(strings.TrimSuffix(t, "s")) {
	case "user":
		return KindUser
	case "computer":
		return KindComputer
	case "group":
		return KindGroup
	case "domain":
		return KindDomain
	case "gpo":
		return KindGPO
	case "ou":
		return KindOU
	case "container":
		return KindContainer
	case "certtemplate":
		return KindCertTemplate
	case "enterpriseca":
		return KindEnterpriseCA
	case "rootca":
		return KindRootCA
	case "aiaca":
		return KindAIACA
	case "ntauthstore":
		return KindNTAuthStore
	}
	return KindUnknown
}
