// Package score turns anonymized path features into ranked risk. It exposes one
// interface with two implementations that are drop-in interchangeable:
//
//   - Distilled: a small model embedded in the client. Runs OFFLINE, zero network.
//   - API:       posts the tokenized features to the Harbinger server (full model).
//
// The client defaults to Distilled. The API scorer is used ONLY when the user
// explicitly supplies an API key, i.e. opts in to hybrid mode.
package score

import (
	"context"

	"github.com/harbingerlabs/harbinger-cli/internal/features"
)

// PathScore is the model output for one path token.
type PathScore struct {
	Token        string  `json:"token"`
	SuccessProb  float64 `json:"success_prob"`  // P(attack chain works)
	EvasionProb  float64 `json:"evasion_prob"`  // P(evades current detection)
	CombinedRank float64 `json:"combined_rank"` // reachable-AND-undetected risk
}

// Response is the model's scores plus provenance.
type Response struct {
	ModelVersion string      `json:"model_version"`
	Tier         string      `json:"tier"`
	Scores       []PathScore `json:"scores"`
}

// Scorer scores a tokenized feature payload.
type Scorer interface {
	Score(ctx context.Context, req *features.ScoreRequest) (*Response, error)
	// Name identifies the scorer for the report footer ("offline-distilled" vs "server-full").
	Name() string
	// Transmits reports whether using this scorer sends data off the machine.
	Transmits() bool
}
