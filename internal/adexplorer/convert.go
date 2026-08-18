package adexplorer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

// userAccountControl bits we care about.
const (
	uacAccountDisable      = 0x00000002
	uacServerTrustAccount  = 0x00002000 // domain controller
	uacTrustedForDelegate  = 0x00080000 // unconstrained delegation
	uacTrustedToAuthDelega = 0x01000000 // constrained delegation w/ protocol transition
	uacDontReqPreauth      = 0x00400000
)

// Ingest reads an AD Explorer snapshot and returns the normalized control graph
// plus a load report. It is the .dat counterpart of parse.Ingest.
//
// A snapshot is untrusted input. Every decode path is bounds-checked, and this
// function additionally recovers from any panic so that a malformed file
// produces an actionable error instead of a stack trace in front of a customer.
func Ingest(path string) (g *parse.Graph, rep *parse.Report, err error) {
	defer func() {
		if r := recover(); r != nil {
			g, rep = nil, nil
			err = fmt.Errorf("this AD Explorer snapshot could not be read (internal error at %v).\n"+
				"  The file is likely corrupt or truncated. Re-take the snapshot with AD Explorer\n"+
				"  (File > Create Snapshot) and make sure it finishes before copying it.", r)
		}
	}()

	s, err := Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer s.Close()

	c := &converter{
		s:       s,
		g:       parse.NewGraph(),
		byDN:    make(map[string]string, s.Len()),
		kindOf:  make(map[string]parse.Kind, s.Len()),
		byHost:  map[string]string{},
		domains: map[string]string{},
	}

	c.indexPass()
	c.buildPass()
	parse.SynthesizeDCSync(c.g)

	rep = &parse.Report{
		Sources:  []string{fmt.Sprintf("%s (AD Explorer snapshot of %s)", baseName(path), displayServer(s))},
		Counts:   map[parse.Kind]int{},
		Warnings: s.Warnings,
	}
	for k, v := range c.g.LoadCounts {
		rep.Counts[k] = v
	}
	rep.Edges = len(c.g.Edges)
	rep.Dangling = c.g.CountUnresolved()

	// An AD Explorer snapshot is an LDAP dump. Saying so is the difference
	// between "no path found" meaning safe and meaning we could not see.
	rep.Gaps = append(rep.Gaps,
		"Sessions were not collected — paths that start from a logged-on user's credential are invisible in this run.",
		"Local group membership (AdminTo / CanRDP / CanPSRemote) was not collected — host-to-host lateral movement is invisible in this run.",
	)
	rep.Modality = "AD Explorer snapshot (LDAP only)"

	if len(c.g.Nodes) == 0 {
		return nil, nil, fmt.Errorf("this snapshot contains no directory objects with a resolvable identity.\n" +
			"  AD Explorer must be connected to a domain naming context (e.g. DC=corp,DC=local),\n" +
			"  not to the RootDSE or the schema, when the snapshot is taken.")
	}
	return c.g, rep, nil
}

type converter struct {
	s *Snapshot
	g *parse.Graph

	byDN   map[string]string     // lowercased DN -> object identifier
	kindOf map[string]parse.Kind // object identifier -> kind
	byHost map[string]string     // lowercased hostname (fqdn and short) -> computer id

	domains map[string]string // domain SID -> DNS name
}

// indexPass records identity for every object so that DN-valued attributes
// (member, gPLink, containment) can be resolved in the second pass.
func (c *converter) indexPass() {
	for i := 0; i < c.s.Len(); i++ {
		o, err := c.s.Object(i)
		if err != nil {
			c.s.warn("object %d skipped: %v", i, err)
			continue
		}
		dn := o.Str("distinguishedName")
		if dn == "" {
			continue
		}
		kind := kindOf(o, dn)
		id := identifierOf(o, kind)
		if id == "" {
			continue
		}
		c.byDN[strings.ToLower(dn)] = id
		c.kindOf[id] = kind

		if kind == parse.KindDomain {
			c.domains[id] = DomainPart(dn)
		}
		if kind == parse.KindComputer {
			if h := strings.ToLower(o.Str("dNSHostName")); h != "" {
				c.byHost[h] = id
				if short, _, ok := strings.Cut(h, "."); ok {
					c.byHost[short] = id
				}
			}
			if sam := strings.ToLower(strings.TrimSuffix(o.Str("sAMAccountName"), "$")); sam != "" {
				if _, dup := c.byHost[sam]; !dup {
					c.byHost[sam] = id
				}
			}
		}
	}
}

// buildPass emits nodes and edges.
func (c *converter) buildPass() {
	for i := 0; i < c.s.Len(); i++ {
		o, err := c.s.Object(i)
		if err != nil {
			continue
		}
		dn := o.Str("distinguishedName")
		if dn == "" {
			continue
		}
		kind := kindOf(o, dn)
		id := identifierOf(o, kind)
		if id == "" {
			continue
		}

		uac, hasUAC := o.Int("userAccountControl")
		n := &parse.Node{
			ID:        id,
			Kind:      kind,
			Name:      c.displayName(o, dn, kind),
			DomainSID: domainSIDOf(id),
			Enabled:   !hasUAC || uac&uacAccountDisable == 0,
		}
		if ac, ok := o.Int("adminCount"); ok && ac != 0 {
			n.AdminCount = true
		}
		if hasUAC {
			n.Unconstr = uac&uacTrustedForDelegate != 0
			n.IsDC = kind == parse.KindComputer && uac&uacServerTrustAccount != 0
		}
		if len(o.Strs("servicePrincipalName")) > 0 {
			n.HasSPN = true
		}
		c.g.AddNode(n)

		c.membership(o, id)
		c.containment(dn, id)
		c.acls(o, id, kind)
		c.delegation(o, id, uac)
		c.sidHistory(o, id)
		c.gpLinks(o, id)
	}
}

// membership emits MemberOf from the `member` attribute and primaryGroupID.
func (c *converter) membership(o *Object, id string) {
	for _, memberDN := range o.Strs("member") {
		if mid, ok := c.byDN[strings.ToLower(memberDN)]; ok {
			c.g.AddEdge(mid, id, parse.MemberOf, false)
		}
	}
	// primaryGroupID is a RID in the account's own domain. Domain Users is the
	// usual value, but a machine account's primary group is Domain Computers and
	// a DC's is Domain Controllers — which is a real Tier Zero membership.
	if rid, ok := o.Int("primaryGroupID"); ok && rid > 0 {
		if dsid := domainSIDOf(id); dsid != "" {
			c.g.AddEdge(id, fmt.Sprintf("%s-%d", dsid, rid), parse.MemberOf, false)
		}
	}
}

// containment emits Contains from an object's parent, which is how a delegated
// OU turns into control of everything under it.
func (c *converter) containment(dn, id string) {
	segs := splitDN(dn)
	if len(segs) < 2 {
		return
	}
	parentDN := strings.Join(segs[1:], ",")
	if pid, ok := c.byDN[strings.ToLower(parentDN)]; ok && pid != id {
		c.g.AddEdge(pid, id, parse.Contains, false)
	}
}

// acls turns the object's security descriptor into control edges. This is the
// substance of the analysis.
func (c *converter) acls(o *Object, id string, kind parse.Kind) {
	sd := o.Bytes("nTSecurityDescriptor")
	if len(sd) == 0 {
		return
	}
	owner, edges := parseSecurityDescriptor(sd, kind)
	if owner != "" && !isNoiseSource(owner) {
		c.g.AddEdge(owner, id, parse.Owns, true)
	}
	for _, e := range edges {
		c.g.AddEdge(e.From, id, e.Type, e.Type.IsACL())
	}

	// A gMSA's password readers live in their own descriptor attribute.
	if gsd := o.Bytes("msDS-GroupMSAMembership"); len(gsd) > 0 {
		_, readers := parseSecurityDescriptor(gsd, kind)
		for _, e := range readers {
			c.g.AddEdge(e.From, id, parse.ReadGMSAPassword, true)
		}
	}
}

// delegation emits constrained delegation (msDS-AllowedToDelegateTo) and
// resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity).
func (c *converter) delegation(o *Object, id string, uac int64) {
	for _, spn := range o.Strs("msDS-AllowedToDelegateTo") {
		// SPN form: "service/host.fqdn:port/extra" — the host is what matters.
		_, rest, ok := strings.Cut(spn, "/")
		if !ok {
			continue
		}
		host := strings.ToLower(rest)
		if i := strings.IndexAny(host, ":/"); i >= 0 {
			host = host[:i]
		}
		if tid, ok := c.byHost[host]; ok && tid != id {
			c.g.AddEdge(id, tid, parse.AllowedToDelegate, false)
		}
	}
	if sd := o.Bytes("msDS-AllowedToActOnBehalfOfOtherIdentity"); len(sd) > 0 {
		_, actors := parseSecurityDescriptor(sd, parse.KindComputer)
		for _, a := range actors {
			c.g.AddEdge(a.From, id, parse.AllowedToAct, false)
		}
	}
	_ = uac
}

// sidHistory: holding another principal's historical SID grants its access.
func (c *converter) sidHistory(o *Object, id string) {
	for _, v := range o.Attr("sIDHistory") {
		if s := SIDString(v.Raw); s != "" {
			c.g.AddEdge(id, s, parse.HasSIDHistory, false)
		}
	}
}

// gpLinks: a GPO linked to an OU or domain controls every computer beneath it.
func (c *converter) gpLinks(o *Object, id string) {
	raw := o.Str("gPLink")
	if raw == "" {
		return
	}
	for _, link := range parseGPLink(raw) {
		if gid, ok := c.byDN[strings.ToLower(link)]; ok {
			c.g.AddEdge(gid, id, parse.GPLink, false)
		}
	}
}

// parseGPLink splits the packed gPLink attribute, skipping disabled links.
// Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=x;0][LDAP://...;1]
// The trailing flag is a bitmask: bit 0 set means the link is disabled.
func parseGPLink(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, "[") {
		part = strings.TrimSuffix(strings.TrimSpace(part), "]")
		if part == "" {
			continue
		}
		body, flag, ok := strings.Cut(part, ";")
		if ok && len(flag) > 0 && (flag[0]-'0')&1 == 1 {
			continue // link disabled
		}
		body = strings.TrimPrefix(body, "]")
		if i := strings.Index(strings.ToUpper(body), "LDAP://"); i >= 0 {
			body = body[i+len("LDAP://"):]
		}
		if body = strings.TrimSpace(body); body != "" {
			out = append(out, body)
		}
	}
	return out
}

// displayName builds the BloodHound-style SAMACCOUNTNAME@DOMAIN.FQDN label so a
// snapshot report reads identically to a SharpHound one.
func (c *converter) displayName(o *Object, dn string, kind parse.Kind) string {
	domain := DomainPart(dn)
	if kind == parse.KindDomain {
		return domain
	}
	base := o.Str("sAMAccountName")
	if base == "" {
		base = o.Str("name")
	}
	if base == "" {
		base = firstRDN(dn)
	}
	if base == "" {
		return domain
	}
	if domain == "" {
		return strings.ToUpper(base)
	}
	return strings.ToUpper(base) + "@" + domain
}

// ---- object classification ----

// kindOf classifies an object from its objectClass chain, most specific first.
func kindOf(o *Object, dn string) parse.Kind {
	classes := map[string]bool{}
	for _, c := range o.Strs("objectClass") {
		classes[strings.ToLower(c)] = true
	}
	switch {
	case classes["computer"] || classes["msds-managedserviceaccount"] && classes["computer"]:
		return parse.KindComputer
	case classes["group"]:
		return parse.KindGroup
	case classes["domaindns"]:
		return parse.KindDomain
	case classes["organizationalunit"]:
		return parse.KindOU
	case classes["grouppolicycontainer"]:
		return parse.KindGPO
	case classes["pkicertificatetemplate"]:
		return parse.KindCertTemplate
	case classes["pkienrollmentservice"]:
		return parse.KindEnterpriseCA
	case classes["certificationauthority"]:
		u := strings.ToUpper(dn)
		switch {
		case strings.Contains(u, "CN=NTAUTHCERTIFICATES"):
			return parse.KindNTAuthStore
		case strings.Contains(u, "CN=AIA"):
			return parse.KindAIACA
		default:
			return parse.KindRootCA
		}
	case classes["user"] || classes["msds-groupmanagedserviceaccount"] || classes["inetorgperson"]:
		return parse.KindUser
	case classes["container"]:
		return parse.KindContainer
	}
	return parse.KindUnknown
}

// identifierOf returns the graph identity for an object: the SID for security
// principals, the GUID for everything else — matching BloodHound, so the two
// input formats produce comparable graphs.
func identifierOf(o *Object, kind parse.Kind) string {
	switch kind {
	case parse.KindUser, parse.KindComputer, parse.KindGroup, parse.KindDomain:
		for _, v := range o.Attr("objectSid") {
			if s := SIDString(v.Raw); s != "" {
				return strings.ToUpper(s)
			}
		}
	}
	for _, v := range o.Attr("objectGUID") {
		if g := GUIDString(v.Raw); g != "" {
			return g
		}
	}
	// A security principal with no SID is not usable in a control graph.
	for _, v := range o.Attr("objectSid") {
		if s := SIDString(v.Raw); s != "" {
			return strings.ToUpper(s)
		}
	}
	return ""
}

// ---- small helpers ----

func domainSIDOf(sid string) string {
	if !strings.HasPrefix(strings.ToUpper(sid), "S-1-5-21-") {
		return ""
	}
	i := strings.LastIndex(sid, "-")
	if i <= 0 {
		return ""
	}
	return strings.ToUpper(sid[:i])
}

func firstRDN(dn string) string {
	segs := splitDN(dn)
	if len(segs) == 0 {
		return ""
	}
	if _, v, ok := strings.Cut(segs[0], "="); ok {
		return v
	}
	return segs[0]
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func displayServer(s *Snapshot) string {
	if s.Server != "" {
		return s.Server
	}
	return "unknown server"
}

// Domains lists the domain SIDs seen, sorted, for multi-tenant reporting.
func (c *converter) Domains() []string {
	out := make([]string, 0, len(c.domains))
	for k := range c.domains {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
