package parse

import (
	"fmt"
	"strings"
)

// Real exports reference principals that are not in the collection: a trust
// partner's group, an account deleted years ago, a built-in the collector did
// not enumerate. BloodHound calls these dangling SIDs and so do we.
//
// Printing a raw SID in a customer-facing report is a defect: the reader cannot
// tell whether it is important or an artifact. Every unresolved principal gets
// the best name we can honestly give it, and is labelled as unresolved.

// wellKnownRIDNames are domain-relative identifiers with fixed meanings.
var wellKnownRIDNames = map[string]string{
	"498": "Enterprise Read-only Domain Controllers",
	"500": "Administrator",
	"501": "Guest",
	"502": "krbtgt",
	"512": "Domain Admins",
	"513": "Domain Users",
	"514": "Domain Guests",
	"515": "Domain Computers",
	"516": "Domain Controllers",
	"517": "Cert Publishers",
	"518": "Schema Admins",
	"519": "Enterprise Admins",
	"520": "Group Policy Creator Owners",
	"521": "Read-only Domain Controllers",
	"522": "Cloneable Domain Controllers",
	"525": "Protected Users",
	"526": "Key Admins",
	"527": "Enterprise Key Admins",
	"553": "RAS and IAS Servers",
	"571": "Allowed RODC Password Replication Group",
	"572": "Denied RODC Password Replication Group",
}

// wellKnownAbsoluteNames are SIDs whose meaning does not depend on a domain.
var wellKnownAbsoluteNames = map[string]string{
	"S-1-0-0":      "Null Authority",
	"S-1-1-0":      "Everyone",
	"S-1-2-0":      "Local",
	"S-1-3-0":      "Creator Owner",
	"S-1-3-1":      "Creator Group",
	"S-1-5-2":      "Network",
	"S-1-5-4":      "Interactive",
	"S-1-5-6":      "Service",
	"S-1-5-7":      "Anonymous",
	"S-1-5-9":      "Enterprise Domain Controllers",
	"S-1-5-10":     "Self",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-13":     "Terminal Server Users",
	"S-1-5-14":     "Remote Interactive Logon",
	"S-1-5-15":     "This Organization",
	"S-1-5-17":     "IUSR",
	"S-1-5-18":     "Local System",
	"S-1-5-19":     "Local Service",
	"S-1-5-20":     "Network Service",
	"S-1-5-32-544": "Administrators (BUILTIN)",
	"S-1-5-32-545": "Users (BUILTIN)",
	"S-1-5-32-546": "Guests (BUILTIN)",
	"S-1-5-32-548": "Account Operators (BUILTIN)",
	"S-1-5-32-549": "Server Operators (BUILTIN)",
	"S-1-5-32-550": "Print Operators (BUILTIN)",
	"S-1-5-32-551": "Backup Operators (BUILTIN)",
	"S-1-5-32-552": "Replicators (BUILTIN)",
	"S-1-5-32-554": "Pre-Windows 2000 Compatible Access (BUILTIN)",
	"S-1-5-32-555": "Remote Desktop Users (BUILTIN)",
	"S-1-5-32-556": "Network Configuration Operators (BUILTIN)",
	"S-1-5-32-557": "Incoming Forest Trust Builders (BUILTIN)",
	"S-1-5-32-558": "Performance Monitor Users (BUILTIN)",
	"S-1-5-32-559": "Performance Log Users (BUILTIN)",
	"S-1-5-32-560": "Windows Authorization Access Group (BUILTIN)",
	"S-1-5-32-562": "Distributed COM Users (BUILTIN)",
	"S-1-5-32-568": "IIS_IUSRS (BUILTIN)",
	"S-1-5-32-569": "Cryptographic Operators (BUILTIN)",
	"S-1-5-32-573": "Event Log Readers (BUILTIN)",
	"S-1-5-32-574": "Certificate Service DCOM Access (BUILTIN)",
	"S-1-5-32-578": "Hyper-V Administrators (BUILTIN)",
	"S-1-5-32-579": "Access Control Assistance Operators (BUILTIN)",
	"S-1-5-32-580": "Remote Management Users (BUILTIN)",
}

// WellKnownName returns a human name for a SID whose object was not collected,
// or "" when the SID has no well-known meaning.
func WellKnownName(sid string) string {
	u := strings.ToUpper(strings.TrimSpace(sid))
	if n, ok := wellKnownAbsoluteNames[u]; ok {
		return n
	}
	if strings.HasPrefix(u, "S-1-5-21-") {
		if i := strings.LastIndex(u, "-"); i > 0 {
			if n, ok := wellKnownRIDNames[u[i+1:]]; ok {
				return n
			}
		}
	}
	return ""
}

// DisplayName is the single place that decides how a principal is shown to a
// user. Unresolved principals are never rendered as a bare SID.
func DisplayName(n *Node) string {
	if n == nil {
		return "(unknown principal)"
	}
	if n.Name != "" {
		return n.Name
	}
	if wk := WellKnownName(n.ID); wk != "" {
		return fmt.Sprintf("%s (not in this collection)", wk)
	}
	if n.Kind != KindUnknown && n.Kind != "" {
		return fmt.Sprintf("unresolved %s %s", strings.ToLower(string(n.Kind)), shortSID(n.ID))
	}
	return fmt.Sprintf("unresolved principal %s", shortSID(n.ID))
}

// shortSID keeps a SID identifiable without dominating a report line: the
// domain portion is elided, the RID kept, because the RID is what an admin
// actually looks up.
func shortSID(sid string) string {
	u := strings.ToUpper(sid)
	if !strings.HasPrefix(u, "S-1-5-21-") {
		return u
	}
	if i := strings.LastIndex(u, "-"); i > 0 {
		return "…-" + u[i+1:]
	}
	return u
}

// Unresolved reports whether a node is a stub created by a dangling reference
// rather than a collected object.
func (n *Node) Unresolved() bool { return n != nil && n.Name == "" && n.Kind == KindUnknown }
