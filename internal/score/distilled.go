package score

import (
	"context"
	"math"

	"github.com/harbingerlabs/harbinger-cli/internal/features"
)

// DistilledModelVersion identifies the embedded weights. Bump when they change.
const DistilledModelVersion = "distilled-1.0.0"

// Distilled is the embedded, fully-local scorer. It is deliberately simple and
// auditable: a logistic blend over the same structural features the server
// consumes, anchored to the per-edge priors. It is LOWER QUALITY than the
// server's ρ-calibrated model — that trade is the price of zero transmission.
type Distilled struct{}

func (Distilled) Name() string    { return "offline-distilled" }
func (Distilled) Transmits() bool { return false }

// distilled logistic weights (the "model"). These are hand-calibrated priors,
// not fitted parameters; the server holds the trained model.
const (
	wHopPenalty  = 0.18 // each hop reduces success odds
	wACLNoise    = 0.22 // ACL edges are comparatively loud
	wExecNoise   = 0.30 // exec/session edges are the loudest
	wReplBonus   = 0.35 // replication/DCSync is quiet + decisive
	wCrossDomain = 0.25 // cross-domain paths are rarer / higher signal
	wADCSBonus   = 0.20
)

func (Distilled) Score(_ context.Context, req *features.ScoreRequest) (*Response, error) {
	resp := &Response{ModelVersion: DistilledModelVersion, Tier: "free"}
	for _, f := range req.Features {
		v := f.PathFeatures

		// Success: start from the multiplicative prior, penalize length.
		succ := v.SuccessPrior * math.Exp(-wHopPenalty*float64(max(0, v.Hops-1)))
		succ = clamp01(succ)

		// Evasion: start from the evasion prior, then adjust by edge composition.
		// More exec/ACL edges -> louder -> lower evasion; replication/ADCS -> quieter.
		logit := logit(clampEps(v.EvasionPrior))
		logit -= wExecNoise * float64(v.NumExecEdges)
		logit -= wACLNoise * float64(v.NumACLEdges) * 0.5
		if v.NumReplEdges > 0 || v.HasDCSync {
			logit += wReplBonus
		}
		if v.HasADCS {
			logit += wADCSBonus
		}
		if v.CrossesDomain {
			logit += wCrossDomain
		}
		evade := sigmoid(logit)

		resp.Scores = append(resp.Scores, PathScore{
			Token:        f.Token,
			SuccessProb:  round4(succ),
			EvasionProb:  round4(evade),
			CombinedRank: round4(succ * evade),
		})
	}
	return resp, nil
}

func sigmoid(x float64) float64 { return 1 / (1 + math.Exp(-x)) }
func logit(p float64) float64   { return math.Log(p / (1 - p)) }

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
func clampEps(x float64) float64 {
	const eps = 1e-4
	if x < eps {
		return eps
	}
	if x > 1-eps {
		return 1 - eps
	}
	return x
}
func round4(x float64) float64 { return math.Round(x*1e4) / 1e4 }
