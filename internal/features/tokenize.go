// Package features is THE privacy boundary. It converts concrete attack paths
// (full of SIDs, names, GUIDs) into anonymized, tokenized structural features.
//
// Invariant enforced by tests (tokenize_test.go, extract_test.go):
//
//	The JSON of a ScoreRequest contains NO identity-bearing string from the
//	source graph — no name, SID, GUID, domain, SPN, or description. Only
//	per-run random tokens and coarse structural enums/counts.
//
// The real-identity <-> token map lives only in Mapping, in memory, and is used
// locally to render the report. It is never serialized into an outbound request.
package features

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Tokenizer assigns per-run random tokens to node identities. Two runs of the
// same export produce different tokens; the server cannot correlate runs or
// recover identities.
type Tokenizer struct {
	RunToken string            // random per invocation
	nodeTok  map[string]string // realID -> token
	revTok   map[string]string // token -> realID (LOCAL ONLY)
	counter  int
}

// NewTokenizer seeds a run with cryptographically-random tokens.
func NewTokenizer() *Tokenizer {
	return &Tokenizer{
		RunToken: "run_" + randHex(8),
		nodeTok:  map[string]string{},
		revTok:   map[string]string{},
	}
}

// Node returns the stable-within-run token for a real node id.
func (t *Tokenizer) Node(realID string) string {
	if tok, ok := t.nodeTok[realID]; ok {
		return tok
	}
	t.counter++
	// salt the token with the run token so tokens are not globally guessable.
	tok := fmt.Sprintf("n_%s_%05d", t.RunToken[4:8], t.counter)
	t.nodeTok[realID] = tok
	t.revTok[tok] = realID
	return tok
}

// Real reverses a token back to its identity (LOCAL rendering only).
func (t *Tokenizer) Real(token string) (string, bool) {
	r, ok := t.revTok[token]
	return r, ok
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should not fail; if it does, fail loud rather than emit a
		// predictable token.
		panic("harbinger: secure RNG unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)[:n]
}
