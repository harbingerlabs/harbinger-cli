package features

import (
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
	"github.com/harbingerlabs/harbinger-cli/internal/pathfind"
)

// SchemaVersion is the wire schema for the outbound feature payload. Bump on any
// change to what is transmitted; the server negotiates against it.
const SchemaVersion = "1.0.0"

// ScoreRequest is the ENTIRE payload that may leave the machine in hybrid mode.
// Read this struct to know exactly what is transmitted. There is nothing else.
type ScoreRequest struct {
	ClientVersion string        `json:"client_version"`
	SchemaVersion string        `json:"schema_version"`
	RunToken      string        `json:"run_token"`
	Features      []PathFeature `json:"features"`
}

// PathFeature describes one candidate path with identity stripped out.
type PathFeature struct {
	Token        string        `json:"token"`    // per-run random path token
	Nodes        []string      `json:"nodes"`    // per-run random node tokens (motif structure only)
	EndKind      string        `json:"end_kind"` // HVT object kind (e.g. "Group","Domain")
	StartKind    string        `json:"start_kind"`
	PathFeatures PathVector    `json:"path_features"`
	EdgeFeatures []EdgeFeature `json:"edge_features"`
}

// PathVector is the numeric/categorical feature vector for the whole path.
type PathVector struct {
	Hops             int     `json:"hops"`
	NumACLEdges      int     `json:"num_acl_edges"`
	NumExecEdges     int     `json:"num_exec_edges"`
	NumDelegEdges    int     `json:"num_deleg_edges"`
	NumReplEdges     int     `json:"num_repl_edges"`
	DistinctEdgeType int     `json:"distinct_edge_types"`
	CrossesDomain    bool    `json:"crosses_domain"`
	HasDCSync        bool    `json:"has_dcsync"`
	HasADCS          bool    `json:"has_adcs"`
	MinOutDegBucket  int     `json:"min_out_deg_bucket"`
	MeanOutDegBucket int     `json:"mean_out_deg_bucket"`
	SuccessPrior     float64 `json:"success_prior"` // product of per-edge success
	EvasionPrior     float64 `json:"evasion_prior"` // product of per-edge (1-detection)
}

// EdgeFeature is one step, identity stripped: only the categorical edge type and
// coarse structural buckets.
type EdgeFeature struct {
	EType     string `json:"etype"`
	SrcKind   string `json:"src_kind"`
	DstKind   string `json:"dst_kind"`
	SrcDegBkt int    `json:"src_deg_bucket"`
	DstDegBkt int    `json:"dst_deg_bucket"`
	IsACL     bool   `json:"is_acl"`
}

// Mapping is the LOCAL-ONLY correlation between transmitted tokens and reality.
// It never leaves the process.
type Mapping struct {
	Tok       *Tokenizer
	PathIndex map[string]int // path token -> index into the original []Path
}

// Extract builds the outbound ScoreRequest and the local Mapping. This is the
// only function that decides what is eligible to be transmitted.
func Extract(g *parse.Graph, paths []pathfind.Path, clientVersion string) (*ScoreRequest, *Mapping) {
	tok := NewTokenizer()
	req := &ScoreRequest{
		ClientVersion: clientVersion,
		SchemaVersion: SchemaVersion,
		RunToken:      tok.RunToken,
	}
	m := &Mapping{Tok: tok, PathIndex: map[string]int{}}

	for i, p := range paths {
		pt := tok.Node("path:" + p.Key())
		m.PathIndex[pt] = i

		pf := PathFeature{Token: pt}
		for _, n := range p.Nodes {
			pf.Nodes = append(pf.Nodes, tok.Node(n))
		}
		pf.StartKind = kindOf(g, p.Nodes[0])
		pf.EndKind = kindOf(g, p.Nodes[len(p.Nodes)-1])

		vec := PathVector{Hops: len(p.Edges), SuccessPrior: 1, EvasionPrior: 1}
		seenType := map[parse.EdgeType]bool{}
		var degSum, degN int
		minDeg := 1 << 30
		for _, e := range p.Edges {
			prof := e.Type.Profile()
			vec.SuccessPrior *= prof.Success
			vec.EvasionPrior *= (1 - prof.Detection)
			seenType[e.Type] = true
			if e.Type.IsACL() {
				vec.NumACLEdges++
			}
			switch e.Type {
			case parse.AdminTo, parse.CanRDP, parse.CanPSRemote, parse.ExecuteDCOM, parse.SQLAdmin, parse.HasSession:
				vec.NumExecEdges++
			case parse.AllowedToDelegate, parse.AllowedToAct:
				vec.NumDelegEdges++
			case parse.DCSync, parse.GetChanges, parse.GetChangesAll:
				vec.NumReplEdges++
			}
			if e.Type == parse.DCSync {
				vec.HasDCSync = true
			}
			if e.Type == parse.ADCSESC {
				vec.HasADCS = true
			}
			d := g.OutDegree(e.From)
			degSum += d
			degN++
			if d < minDeg {
				minDeg = d
			}
			pf.EdgeFeatures = append(pf.EdgeFeatures, EdgeFeature{
				EType:     string(e.Type),
				SrcKind:   kindOf(g, e.From),
				DstKind:   kindOf(g, e.To),
				SrcDegBkt: degBucket(g.OutDegree(e.From)),
				DstDegBkt: degBucket(g.OutDegree(e.To)),
				IsACL:     e.Type.IsACL(),
			})
		}
		vec.DistinctEdgeType = len(seenType)
		if degN > 0 {
			vec.MeanOutDegBucket = degBucket(degSum / degN)
			vec.MinOutDegBucket = degBucket(minDeg)
		}
		vec.CrossesDomain = crossesDomain(g, p.Nodes)
		pf.PathFeatures = vec
		req.Features = append(req.Features, pf)
	}
	return req, m
}

func kindOf(g *parse.Graph, id string) string {
	if n := g.Node(id); n != nil {
		return string(n.Kind)
	}
	return string(parse.KindUnknown)
}

func crossesDomain(g *parse.Graph, nodes []string) bool {
	first := ""
	for _, id := range nodes {
		n := g.Node(id)
		if n == nil || n.DomainSID == "" {
			continue
		}
		if first == "" {
			first = n.DomainSID
		} else if n.DomainSID != first {
			return true
		}
	}
	return false
}

// degBucket coarsens a degree so it cannot fingerprint a specific object.
func degBucket(d int) int {
	switch {
	case d <= 0:
		return 0
	case d == 1:
		return 1
	case d <= 3:
		return 2
	case d <= 7:
		return 3
	case d <= 15:
		return 4
	case d <= 31:
		return 5
	default:
		return 6
	}
}
