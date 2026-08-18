// Package hvt resolves High-Value Targets (Tier Zero) in a normalized graph.
package hvt

import (
	"fmt"
	"sort"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

// wellKnownTierZeroRIDs are the domain-relative RIDs whose groups/accounts are
// Tier Zero by definition (control of them is game-over for the domain).
var wellKnownTierZeroRIDs = map[string]string{
	"512": "Domain Admins",
	"519": "Enterprise Admins",
	"518": "Schema Admins",
	"516": "Domain Controllers",
	"521": "Read-only Domain Controllers",
	"526": "Key Admins",
	"527": "Enterprise Key Admins",
	"548": "Account Operators",
	"549": "Server Operators",
	"550": "Print Operators",
	"551": "Backup Operators",
	"500": "Administrator",
	"502": "krbtgt",
}

// wellKnownTierZeroSIDs are absolute well-known SIDs (BUILTIN\Administrators).
var wellKnownTierZeroSIDs = map[string]string{
	"S-1-5-32-544": "Administrators (BUILTIN)",
	"S-1-5-32-551": "Backup Operators (BUILTIN)",
	"S-1-5-32-548": "Account Operators (BUILTIN)",
	"S-1-5-32-549": "Server Operators (BUILTIN)",
}

// Domain describes one directory found in the graph. An MSP's machine holds
// many client directories, so "which domain is this?" is a first-class answer,
// not an assumption.
type Domain struct {
	SID       string
	Name      string // DNS name, when known
	Nodes     int    // principals whose SID belongs to this domain
	Crown     string // Domain Admins of this domain, else the domain object
	CrownName string
}

// Resolved holds the crown target and the full Tier Zero set.
type Resolved struct {
	TierZero map[string]bool // node id -> true
	// Crown: the single most valuable objective (Domain Admins, else the Domain node).
	Crown     string
	CrownName string
	Targets   []string // ordered, de-duplicated HVT ids worth pathing to

	// Domains is every directory present, largest first. Len > 1 means the
	// input spans a forest or several tenants.
	Domains []Domain
	// Scope is the domain the analysis was restricted to, or "" for all.
	Scope string
}

// Resolve marks Tier Zero nodes across every domain in the graph.
// `override` is an optional set of SIDs or case-insensitive names the user
// designates as additional HVTs (via --hvt).
func Resolve(g *parse.Graph, override []string) *Resolved {
	r, _ := ResolveScoped(g, override, "")
	return r
}

// ResolveScoped is Resolve restricted to one domain, named by SID or by DNS
// name. It returns an error when the requested domain is not in the graph, so
// an MSP pointing at the wrong client's export is told immediately rather than
// getting a confident report about the wrong directory.
func ResolveScoped(g *parse.Graph, override []string, domainScope string) (*Resolved, error) {
	res := &Resolved{TierZero: map[string]bool{}}
	overSID := map[string]bool{}
	overName := map[string]bool{}
	for _, o := range override {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(o), "S-1-") {
			overSID[strings.ToUpper(o)] = true
		} else {
			overName[strings.ToLower(o)] = true
		}
	}

	// Deterministic iteration: map order must never decide what a customer sees.
	ids := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	daByDomain := map[string]string{}
	domainNodes := map[string]string{} // domain SID -> domain object id
	nodeCount := map[string]int{}

	for _, id := range ids {
		n := g.Nodes[id]
		tz := false
		switch {
		case overSID[strings.ToUpper(id)]:
			tz = true
		case n.Name != "" && overName[strings.ToLower(n.Name)]:
			tz = true
		case wellKnownTierZeroSIDs[strings.ToUpper(id)] != "":
			tz = true
		case n.HighValue:
			tz = true
		}
		// RID-based (last hyphen segment).
		if rid := ridOf(id); rid != "" {
			if _, ok := wellKnownTierZeroRIDs[rid]; ok {
				tz = true
				if rid == "512" {
					daByDomain[DomainSIDOf(id)] = id
				}
			}
		}
		// ADCS Tier Zero object kinds.
		switch n.Kind {
		case parse.KindEnterpriseCA, parse.KindRootCA, parse.KindNTAuthStore, parse.KindAIACA:
			tz = true
		case parse.KindDomain:
			domainNodes[strings.ToUpper(id)] = id
			// The domain object is Tier Zero in its own right. Rights over it
			// — DCSync, Owns, WriteDacl, GenericAll — are domain compromise
			// without ever touching the Domain Admins group: DCSync alone
			// extracts every credential in the directory, krbtgt included.
			//
			// Leaving it off the objective list meant a service account holding
			// replication rights was reported only if some later hop happened to
			// reach the group, and silently dropped otherwise. On a directory
			// where a "temporary" DCSync grant was the single most serious
			// finding, the report did not mention it.
			tz = true
		}
		if n.IsDC {
			tz = true
		}
		if tz {
			res.TierZero[id] = true
			n.TierZero = true
		}
		if d := DomainSIDOf(id); d != "" {
			nodeCount[d]++
		}
	}

	res.Domains = buildDomains(g, domainNodes, daByDomain, nodeCount)

	// Restrict to one directory if the caller asked for it.
	if domainScope = strings.TrimSpace(domainScope); domainScope != "" {
		d := matchDomain(res.Domains, domainScope)
		if d == nil {
			return res, fmt.Errorf("no domain matching %q in this export.\n  Domains present: %s", domainScope, domainList(res.Domains))
		}
		res.Scope = d.SID
		res.Crown, res.CrownName = d.Crown, d.CrownName
		// Tier Zero outside the selected domain is not an objective here.
		for id := range res.TierZero {
			if DomainSIDOf(id) != d.SID && strings.ToUpper(id) != strings.ToUpper(d.SID) {
				delete(res.TierZero, id)
			}
		}
	} else {
		// Largest directory wins the crown, deterministically. Every other
		// domain's Tier Zero stays in Targets, so cross-domain paths still rank.
		if len(res.Domains) > 0 {
			res.Crown, res.CrownName = res.Domains[0].Crown, res.Domains[0].CrownName
		}
	}

	if res.Crown == "" {
		// No domain object at all (a partial export): fall back to the
		// lowest-sorted Tier Zero node so the choice is still reproducible.
		tz := make([]string, 0, len(res.TierZero))
		for id := range res.TierZero {
			tz = append(tz, id)
		}
		sort.Strings(tz)
		if len(tz) > 0 {
			res.Crown = tz[0]
		}
	}
	if n := g.Node(res.Crown); n != nil && res.CrownName == "" {
		res.CrownName = displayName(n)
	}

	// Ordered target list: crown first, then the rest sorted.
	rest := make([]string, 0, len(res.TierZero))
	for id := range res.TierZero {
		if id != res.Crown {
			rest = append(rest, id)
		}
	}
	sort.Strings(rest)
	if res.Crown != "" {
		res.Targets = append(res.Targets, res.Crown)
	}
	res.Targets = append(res.Targets, rest...)

	// Objectives are now fixed, so widening Tier Zero cannot add targets.
	expandTierZeroMembership(g, res)
	return res, nil
}

// expandTierZeroMembership marks every principal that is, transitively, a
// member of a Tier Zero group as Tier Zero itself.
//
// Without this, an administrator is treated as an ordinary starting principal,
// and the shortest path to Domain Admins in any real directory is an
// administrator's own membership: "alice.brennan -MemberOf-> DOMAIN ADMINS".
// That scores as the single highest-risk finding in the report, and it is not a
// finding at all — it is the definition of the group. On a directory with three
// admins it takes the top five slots, pushing the genuine escalation route to
// sixth. The cost is not one bad row; it is the reader's trust in every row
// under it.
//
// This runs after the objective list is built, so an admin stops being a
// starting point without becoming a target in their own right.
func expandTierZeroMembership(g *parse.Graph, res *Resolved) {
	queue := make([]string, 0, len(res.TierZero))
	for id := range res.TierZero {
		queue = append(queue, id)
	}
	sort.Strings(queue) // determinism: never let map order decide the report

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		// Edges point member -MemberOf-> group, so members are found by
		// walking inbound from the group.
		for _, e := range g.In(cur) {
			if e.Type != parse.MemberOf || res.TierZero[e.From] {
				continue
			}
			res.TierZero[e.From] = true
			if n := g.Node(e.From); n != nil {
				n.TierZero = true
			}
			queue = append(queue, e.From)
		}
	}
}

// buildDomains assembles the per-domain summary, largest first.
func buildDomains(g *parse.Graph, domainNodes, daByDomain map[string]string, nodeCount map[string]int) []Domain {
	sids := map[string]bool{}
	for s := range domainNodes {
		sids[s] = true
	}
	for s := range daByDomain {
		if s != "" {
			sids[s] = true
		}
	}
	for s := range nodeCount {
		if s != "" {
			sids[s] = true
		}
	}

	out := make([]Domain, 0, len(sids))
	for s := range sids {
		d := Domain{SID: s, Nodes: nodeCount[s]}
		if n := g.Node(s); n != nil {
			d.Name = n.Name
		}
		switch {
		case daByDomain[s] != "":
			d.Crown = daByDomain[s]
		case domainNodes[s] != "":
			d.Crown = domainNodes[s]
		}
		if n := g.Node(d.Crown); n != nil {
			d.CrownName = displayName(n)
		}
		if d.Name == "" && d.CrownName != "" {
			if i := strings.Index(d.CrownName, "@"); i >= 0 {
				d.Name = d.CrownName[i+1:]
			}
		}
		out = append(out, d)
	}
	// Largest first; SID breaks ties so the ordering is total and stable.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Nodes != out[j].Nodes {
			return out[i].Nodes > out[j].Nodes
		}
		return out[i].SID < out[j].SID
	})
	return out
}

func matchDomain(ds []Domain, want string) *Domain {
	w := strings.ToUpper(strings.TrimSpace(want))
	for i := range ds {
		if strings.ToUpper(ds[i].SID) == w || strings.ToUpper(ds[i].Name) == w {
			return &ds[i]
		}
	}
	// Accept a unique prefix of the DNS name ("corp" for "CORP.LOCAL").
	var hit *Domain
	for i := range ds {
		if ds[i].Name != "" && strings.HasPrefix(strings.ToUpper(ds[i].Name), w) {
			if hit != nil {
				return nil // ambiguous
			}
			hit = &ds[i]
		}
	}
	return hit
}

func domainList(ds []Domain) string {
	if len(ds) == 0 {
		return "(none found)"
	}
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		label := d.Name
		if label == "" {
			label = d.SID
		}
		parts = append(parts, fmt.Sprintf("%s (%s, %d principals)", label, d.SID, d.Nodes))
	}
	return strings.Join(parts, "; ")
}

// DomainSIDOf returns the domain portion of a principal SID, or "".
func DomainSIDOf(sid string) string {
	u := strings.ToUpper(sid)
	if !strings.HasPrefix(u, "S-1-5-21-") {
		return ""
	}
	i := strings.LastIndex(u, "-")
	if i <= 0 {
		return ""
	}
	// A domain SID has exactly 4 sub-authorities after S-1-5-21 is stripped;
	// a bare domain SID passed in returns itself.
	if strings.Count(u, "-") == 6 {
		return u
	}
	return u[:i]
}

func ridOf(sid string) string {
	if !strings.HasPrefix(strings.ToUpper(sid), "S-1-5-21-") {
		return ""
	}
	i := strings.LastIndex(sid, "-")
	if i < 0 || i == len(sid)-1 {
		return ""
	}
	return sid[i+1:]
}

func displayName(n *parse.Node) string { return parse.DisplayName(n) }
