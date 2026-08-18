package report

import (
	"encoding/json"
	"io"

	"github.com/harbingerlabs/harbinger-cli/internal/analyze"
	"github.com/harbingerlabs/harbinger-cli/internal/diff"
)

// SchemaAnalysis and SchemaDiff name the shape of --json output.
//
// MSPs pipe this into ticketing and RMM systems, so the wire format is a
// contract, not a debug dump. Every field carries an explicit tag: without one
// the key is whatever the Go field happens to be called, and renaming an
// internal field silently breaks every integration built on it. The version
// gives a consumer something to assert on, and us a way to change the shape
// without breaking them quietly.
const (
	SchemaAnalysis = "harbinger.analysis/1"
	SchemaDiff     = "harbinger.diff/1"
)

// envelope wraps a payload with the schema name and the client that wrote it.
type envelope struct {
	Schema  string `json:"schema"`
	Client  string `json:"client"`
	Payload any    `json:"result"`
}

// JSON writes the full structured result (for CI / integrations). This is the
// user's own data on their own machine; it includes real identities.
func JSON(w io.Writer, r *analyze.Result) error {
	return writeJSON(w, SchemaAnalysis, r.ModelVersion, r)
}

// JSONDiff writes the structured diff result.
func JSONDiff(w io.Writer, d *diff.Result) error {
	v := ""
	if d.T1 != nil {
		v = d.T1.ModelVersion
	}
	return writeJSON(w, SchemaDiff, v, d)
}

func writeJSON(w io.Writer, schema, client string, payload any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope{Schema: schema, Client: client, Payload: payload})
}
