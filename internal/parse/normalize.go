package parse

import "strings"

// normalizeObject turns one BloodHound object (CE or Legacy shape) into a node
// plus its outgoing/incoming attack edges. Field probing tolerates both schemas.
func normalizeObject(g *Graph, obj map[string]any, kind Kind, rep *Report) {
	props := asMap(obj["Properties"])
	if props == nil {
		props = asMap(obj["properties"])
	}

	id := firstStr(obj["ObjectIdentifier"], obj["objectid"], props["objectid"], obj["SID"], props["objectsid"])
	if id == "" {
		return
	}

	n := &Node{
		ID:        id,
		Kind:      kind,
		Name:      firstStr(props["name"], props["displayname"], obj["Name"]),
		DomainSID: firstStr(props["domainsid"], obj["domainsid"]),
		Enabled:   boolOr(props["enabled"], true),
	}
	n.AdminCount = boolOr(props["admincount"], false)
	n.Unconstr = boolOr(props["unconstraineddelegation"], false)
	n.IsDC = boolOr(props["isdc"], false) || boolOr(obj["IsDC"], false)
	n.HasSPN = boolOr(props["hasspn"], false)
	if boolOr(props["highvalue"], false) {
		n.HighValue = true
	}
	g.AddNode(n)

	// --- ACEs: principal --Right--> this object ---
	for _, ace := range toList(obj["Aces"]) {
		m := asMap(ace)
		if m == nil {
			continue
		}
		p := firstStr(m["PrincipalSID"], m["PrincipalID"])
		right := normalizeEdgeType(firstStr(m["RightName"], m["Right"]))
		if right == EdgeUnknown {
			rep.UnknownEdges++
		}
		g.AddEdge(p, id, right, right.IsACL())
	}

	// --- Members: member --MemberOf--> this group ---
	for _, mem := range resultsList(obj["Members"]) {
		m := asMap(mem)
		mid := firstStr(m["ObjectIdentifier"], m["MemberId"], m["MemberID"])
		g.AddEdge(mid, id, MemberOf, false)
	}

	// --- ChildObjects: this container --Contains--> child ---
	for _, ch := range resultsList(obj["ChildObjects"]) {
		m := asMap(ch)
		cid := firstStr(m["ObjectIdentifier"], m["MemberId"])
		g.AddEdge(id, cid, Contains, false)
	}

	// --- GPO links: gpo --GPLink--> this OU/Domain ---
	for _, lk := range resultsList(obj["Links"]) {
		m := asMap(lk)
		gpo := firstStr(m["GUID"], m["GPOId"], m["ObjectIdentifier"])
		g.AddEdge(gpo, id, GPLink, false)
	}

	// --- Computer-local relationships ---
	if kind == KindComputer {
		for _, la := range resultsList(obj["LocalAdmins"]) {
			g.AddEdge(firstStr(asMap(la)["ObjectIdentifier"]), id, AdminTo, false)
		}
		for _, ru := range resultsList(obj["RemoteDesktopUsers"]) {
			g.AddEdge(firstStr(asMap(ru)["ObjectIdentifier"]), id, CanRDP, false)
		}
		for _, pu := range resultsList(obj["PSRemoteUsers"]) {
			g.AddEdge(firstStr(asMap(pu)["ObjectIdentifier"]), id, CanPSRemote, false)
		}
		for _, du := range resultsList(obj["DcomUsers"]) {
			g.AddEdge(firstStr(asMap(du)["ObjectIdentifier"]), id, ExecuteDCOM, false)
		}
		for _, aa := range resultsList(obj["AllowedToAct"]) {
			g.AddEdge(firstStr(asMap(aa)["ObjectIdentifier"]), id, AllowedToAct, false)
		}
		// Sessions: from the computer you can harvest the logged-on user's cred.
		for _, s := range resultsList(obj["Sessions"]) {
			m := asMap(s)
			comp := firstStr(m["ComputerSID"])
			if comp == "" {
				comp = id
			}
			g.AddEdge(comp, firstStr(m["UserSID"]), HasSession, false)
		}
	}

	// --- Delegation targets (users & computers) ---
	for _, d := range toList(obj["AllowedToDelegate"]) {
		g.AddEdge(id, firstStr(asMap(d)["ObjectIdentifier"], d), AllowedToDelegate, false)
	}
	// --- SID history: this principal effectively holds target's SID ---
	for _, sh := range toList(obj["HasSIDHistory"]) {
		g.AddEdge(id, firstStr(asMap(sh)["ObjectIdentifier"], sh), HasSIDHistory, false)
	}
}

// SynthesizeDCSync derives DCSync edges on a graph built by another ingester
// (e.g. an AD Explorer snapshot), which needs the same post-processing.
func SynthesizeDCSync(g *Graph) { synthesizeDCSync(g) }

// synthesizeDCSync adds a DCSync edge for any principal holding both GetChanges
// and GetChangesAll on a domain (BloodHound derives this post-collection).
func synthesizeDCSync(g *Graph) {
	type key struct{ from, to string }
	changes := map[key]bool{}
	changesAll := map[key]bool{}
	for _, e := range g.Edges {
		if _, ok := g.DomainSIDs[e.To]; !ok {
			continue
		}
		switch e.Type {
		case GetChanges:
			changes[key{e.From, e.To}] = true
		case GetChangesAll:
			changesAll[key{e.From, e.To}] = true
		}
	}
	for k := range changes {
		if changesAll[k] {
			g.AddEdge(k.from, k.to, DCSync, false)
		}
	}
}

// ---- tolerant accessors ----

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// resultsList unwraps the CE {"Collected":..,"Results":[...]} envelope OR a bare
// Legacy array, returning the element list either way.
func resultsList(v any) []any {
	if m, ok := v.(map[string]any); ok {
		return toList(m["Results"])
	}
	return toList(v)
}

func toList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func firstStr(vals ...any) string {
	for _, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func boolOr(v any, def bool) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	}
	return def
}
