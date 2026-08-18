// Package parse ingests BloodHound / SharpHound exports (Legacy and CE) and
// normalizes them into one internal Active Directory control graph.
//
// PRIVACY NOTE: every field on Node/Edge below can be identity-bearing (SIDs,
// names, distinguished names). Nothing in this package ever transmits anything.
// It only reads local files. The features package is the sole boundary where a
// subset of *structural* information is extracted and tokenized; see
// internal/features and docs/DATA_HANDLING.md.
package parse

import "strings"

// Kind is a normalized AD object type.
type Kind string

const (
	KindUser         Kind = "User"
	KindComputer     Kind = "Computer"
	KindGroup        Kind = "Group"
	KindDomain       Kind = "Domain"
	KindOU           Kind = "OU"
	KindGPO          Kind = "GPO"
	KindContainer    Kind = "Container"
	KindCertTemplate Kind = "CertTemplate"
	KindEnterpriseCA Kind = "EnterpriseCA"
	KindRootCA       Kind = "RootCA"
	KindAIACA        Kind = "AIACA"
	KindNTAuthStore  Kind = "NTAuthStore"
	KindUnknown      Kind = "Unknown"
)

// Node is one AD principal or object. IDs and names are sensitive and never leave.
type Node struct {
	ID        string // ObjectIdentifier: SID or GUID — SENSITIVE
	Kind      Kind
	Name      string // display name — SENSITIVE
	DomainSID string
	Enabled   bool
	// Flags computed during HVT resolution.
	HighValue bool
	TierZero  bool
	// props retains only a few structurally-relevant, non-transmitted booleans.
	IsDC       bool
	Unconstr   bool // unconstrained delegation
	AdminCount bool
	HasSPN     bool
}

// Edge is one directed attack primitive: From can act on / reach To via Type.
type Edge struct {
	From string
	To   string
	Type EdgeType
	ACL  bool // derived from an ACE
}

// Graph is the normalized directed control graph plus adjacency indexes.
type Graph struct {
	Nodes map[string]*Node
	Edges []Edge
	out   map[string][]int // node id -> edge indexes (outgoing)
	in    map[string][]int // node id -> edge indexes (incoming)

	DomainSIDs map[string]bool
	// Diagnostics: counts of loaded objects per kind and dropped/dangling edges.
	LoadCounts map[Kind]int
}

// NewGraph returns an empty, indexed graph.
func NewGraph() *Graph {
	return &Graph{
		Nodes:      map[string]*Node{},
		out:        map[string][]int{},
		in:         map[string][]int{},
		DomainSIDs: map[string]bool{},
		LoadCounts: map[Kind]int{},
	}
}

// AddNode inserts or merges a node by ID. Later, richer records win on empty fields.
func (g *Graph) AddNode(n *Node) {
	if n == nil || n.ID == "" {
		return
	}
	id := strings.ToUpper(n.ID)
	n.ID = id
	if ex, ok := g.Nodes[id]; ok {
		if ex.Name == "" {
			ex.Name = n.Name
		}
		if ex.Kind == KindUnknown && n.Kind != KindUnknown {
			// stub created by a dangling edge is now backed by a real record:
			// move the load count from Unknown to the resolved kind.
			g.LoadCounts[KindUnknown]--
			g.LoadCounts[n.Kind]++
			ex.Kind = n.Kind
			if n.Kind == KindDomain {
				g.DomainSIDs[id] = true
			}
		}
		if ex.DomainSID == "" {
			ex.DomainSID = n.DomainSID
		}
		ex.HighValue = ex.HighValue || n.HighValue
		ex.TierZero = ex.TierZero || n.TierZero
		ex.IsDC = ex.IsDC || n.IsDC
		ex.Unconstr = ex.Unconstr || n.Unconstr
		ex.AdminCount = ex.AdminCount || n.AdminCount
		ex.HasSPN = ex.HasSPN || n.HasSPN
		ex.Enabled = ex.Enabled || n.Enabled
		return
	}
	g.Nodes[id] = n
	g.LoadCounts[n.Kind]++
	if n.Kind == KindDomain {
		g.DomainSIDs[id] = true
	}
}

// AddEdge appends an edge. Endpoints that are not yet known get a stub node so
// pathfinding does not panic (matching BloodHound, where an ACE can reference a
// principal that is not in the collection).
//
// Whether a stub is a real gap is NOT decided here. BloodHound writes one file
// per object type and computers.json is read before groups.json, so almost
// every ACE on a computer refers forward to a principal that arrives minutes
// later in the load. Counting those as dangling reported 1,317 "dangling refs"
// on a 2,561-object directory whose true count was 44 — a figure that reads to
// an operator as a broken collection and sends them back to re-collect for no
// reason. CountUnresolved settles it after the load instead.
func (g *Graph) AddEdge(from, to string, t EdgeType, acl bool) {
	if from == "" || to == "" || from == to {
		return
	}
	from, to = strings.ToUpper(from), strings.ToUpper(to)
	if _, ok := g.Nodes[from]; !ok {
		g.Nodes[from] = &Node{ID: from, Kind: KindUnknown}
	}
	if _, ok := g.Nodes[to]; !ok {
		g.Nodes[to] = &Node{ID: to, Kind: KindUnknown}
	}
	idx := len(g.Edges)
	g.Edges = append(g.Edges, Edge{From: from, To: to, Type: t, ACL: acl})
	g.out[from] = append(g.out[from], idx)
	g.in[to] = append(g.in[to], idx)
}

// CountUnresolved returns the number of principals referenced by an edge that
// never appeared as a real record anywhere in the collection — a permission
// held by an account that was deleted, or one living in a domain that was not
// collected. Called once the whole export is loaded, so a forward reference
// inside the load is not mistaken for a gap.
func (g *Graph) CountUnresolved() int {
	n := 0
	for _, node := range g.Nodes {
		if node.Kind == KindUnknown {
			n++
		}
	}
	return n
}

// Out returns outgoing edges of a node.
func (g *Graph) Out(id string) []Edge {
	idxs := g.out[strings.ToUpper(id)]
	es := make([]Edge, 0, len(idxs))
	for _, i := range idxs {
		es = append(es, g.Edges[i])
	}
	return es
}

// In returns incoming edges of a node.
func (g *Graph) In(id string) []Edge {
	idxs := g.in[strings.ToUpper(id)]
	es := make([]Edge, 0, len(idxs))
	for _, i := range idxs {
		es = append(es, g.Edges[i])
	}
	return es
}

// OutDegree / InDegree are used as (non-identifying) structural features.
func (g *Graph) OutDegree(id string) int { return len(g.out[strings.ToUpper(id)]) }
func (g *Graph) InDegree(id string) int  { return len(g.in[strings.ToUpper(id)]) }

// Node fetches a node by id (case-insensitive), or nil.
func (g *Graph) Node(id string) *Node { return g.Nodes[strings.ToUpper(id)] }
