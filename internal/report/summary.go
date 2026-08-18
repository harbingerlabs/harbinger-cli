package report

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/analyze"
	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

// Summary is the plain-English layer of the report.
//
// The person who decides whether the fix gets scheduled is usually a
// service-delivery manager, not the senior engineer who could read a path
// diagram. Everything here is written to be understood without knowing what
// "GenericAll" means, while the ranked paths below it stay precise enough for
// the engineer who has to do the work.
type Summary struct {
	// Headline is one sentence: the finding.
	Headline string
	// Verdict is the severity word used to color the finding.
	Verdict string // "exposed" | "watch" | "clear" | "incomplete"
	// Meaning explains the headline in business terms.
	Meaning string
	// Action is the single thing to do next.
	Action string
	// Effort is a plain estimate of what the action costs.
	Effort string
	// Scope names the directory and how the data was collected.
	Scope []string
	// Gaps names what this collection could not see.
	Gaps []string
}

// Summarize builds the plain-English layer from a scored result.
func Summarize(r *analyze.Result) Summary {
	var s Summary
	blind := 0
	for _, p := range r.Paths {
		if p.BlindSpot {
			blind++
		}
	}

	switch {
	case len(r.Paths) == 0:
		s.Verdict = "incomplete"
		s.Headline = "No route to full domain control was found in this collection."
		s.Meaning = "This is a lower bound, not a clean bill of health. Most often it means a " +
			"part of the directory was not collected, so the route exists but is invisible here. " +
			"Read the collection gaps below before treating this as good news."
		s.Action = "Re-collect the missing data named under \"What this run could not see\", then run again."
		s.Effort = "About 20 minutes, mostly waiting on the collection."
	case blind > 0:
		s.Verdict = "exposed"
		s.Headline = fmt.Sprintf("%d route%s to full control of %s would probably not be noticed while it was being used.",
			blind, plural(blind), shortName(r.CrownName))
		s.Meaning = "Someone who compromised one ordinary account could reach complete control of " +
			"this directory, and the steps involved are ones that routine monitoring is unlikely to " +
			"alert on. That combination — reachable and quiet — is what makes it worth fixing " +
			"ahead of louder findings."
		s.Effort = "The top fix below is a single permission change; typically minutes to apply, " +
			"and it should be checked against the account's legitimate use first."
	default:
		s.Verdict = "watch"
		s.Headline = fmt.Sprintf("%d route%s to full control of %s exist, but current monitoring would likely see them in use.",
			len(r.Paths), plural(len(r.Paths)), shortName(r.CrownName))
		s.Meaning = "The routes are real and should still be closed, but detection is on your side " +
			"here: an attacker using them would probably generate an alert. Treat this as planned " +
			"work rather than an emergency."
		s.Effort = "Schedule with normal change control."
	}

	if r.TopFix != nil {
		s.Action = fmt.Sprintf("%s On its own this closes %d of the ranked routes.",
			Remediation(r.TopFix.Edge, r.TopFix.Label, r.TopFix.FromName, r.TopFix.ToName),
			r.TopFix.PathsKilled)
	} else if s.Action == "" {
		s.Action = "No single change closes a majority of the routes; work down the ranked list below."
	}

	// Scope: which file, which directory, collected how. The file is named
	// because an MSP runs this for several clients in a sitting, and a report
	// that cannot be traced back to its export cannot be checked.
	if r.Load != nil && r.Load.Modality != "" {
		line := "Collected from: " + r.Load.Modality
		if r.Load.Input != "" {
			line += " — " + filepath.Base(r.Load.Input)
		}
		s.Scope = append(s.Scope, line)
	}
	switch {
	case r.Scope != "":
		s.Scope = append(s.Scope, "Analysis restricted to: "+domainName(r, r.Scope))
	case len(r.Domains) > 1:
		names := make([]string, 0, len(r.Domains))
		for _, d := range r.Domains {
			label := d.Name
			if label == "" {
				label = d.SID
			}
			names = append(names, fmt.Sprintf("%s (%d principals)", label, d.Nodes))
		}
		s.Scope = append(s.Scope, fmt.Sprintf("This export contains %d directories: %s.",
			len(r.Domains), strings.Join(names, ", ")))
		s.Scope = append(s.Scope, fmt.Sprintf("Objectives were ranked against %s, the largest. "+
			"Re-run with --domain <name> to report on one of the others.", shortName(r.CrownName)))
	case len(r.Domains) == 1 && r.Domains[0].Name != "":
		s.Scope = append(s.Scope, "Directory: "+r.Domains[0].Name)
	}

	if r.Load != nil {
		s.Gaps = append(s.Gaps, r.Load.Gaps...)
	}
	return s
}

// Remediation states the change to make, in the imperative, for one edge.
//
// Not every edge is a permission, and the generic "remove X's <edge> over Y"
// sentence produces nonsense for the ones that are not. A session is the most
// important case: HasSession means an account was signed in to a machine when
// the directory was read, so the edge runs computer -> user and the generic
// phrasing becomes "remove WKS-0038's session over alice.brennan", which is not
// a thing anyone can do. An MSP reads that line out to a client, so it has to
// name an action that exists.
func Remediation(edge parse.EdgeType, label, from, to string) string {
	switch edge {
	case parse.HasSession:
		// from = the machine, to = the signed-in account.
		return fmt.Sprintf("Sign %s out of %s, and stop privileged accounts signing in to it. "+
			"While that session exists, anyone with administrator rights on %s can take those credentials.",
			to, from, shortName(from))
	case parse.AdminTo:
		return fmt.Sprintf("Remove %s's local administrator rights on %s.", from, to)
	case parse.CanRDP:
		return fmt.Sprintf("Remove %s's Remote Desktop access to %s.", from, to)
	case parse.CanPSRemote:
		return fmt.Sprintf("Remove %s's PowerShell Remoting access to %s.", from, to)
	case parse.MemberOf:
		return fmt.Sprintf("Remove %s from %s.", from, to)
	case parse.DCSync:
		return fmt.Sprintf("Remove %s's directory replication rights (Replicating Directory Changes "+
			"and Replicating Directory Changes All) on %s.", from, to)
	case parse.AllowedToDelegate:
		return fmt.Sprintf("Remove %s's constrained delegation to %s.", from, to)
	case parse.Contains:
		return fmt.Sprintf("Review what %s grants over the objects inside %s — "+
			"containment is inherited, so the grant applies to everything under it.", from, to)
	case parse.GPLink:
		return fmt.Sprintf("Review the policy %s applies to %s, and who can edit it.", from, to)
	}
	return fmt.Sprintf("Remove %s's %s over %s.", from, plainEdge(string(edge), label), to)
}

// plainEdge renders an edge type in words a non-engineer can act on, keeping the
// technical name in parentheses for the person who has to make the change.
func plainEdge(name, label string) string {
	if label == "" || strings.EqualFold(label, name) {
		return name
	}
	return fmt.Sprintf("%s (%s)", label, name)
}

func domainName(r *analyze.Result, sid string) string {
	for _, d := range r.Domains {
		if strings.EqualFold(d.SID, sid) && d.Name != "" {
			return d.Name
		}
	}
	return sid
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
