package report

import (
	"strings"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

// The remediation line is the sentence an MSP reads out to a client. A session
// is not a permission and cannot be revoked, so the generic phrasing produced
// "remove WKS-01's session over alice" — an instruction for something nobody
// can do.
func TestSessionRemediationNamesAnActionThatExists(t *testing.T) {
	got := Remediation(parse.HasSession, "harvest live session credential",
		"WKS-01.CORP.LOCAL", "alice@CORP.LOCAL")
	if strings.HasPrefix(got, "Remove") {
		t.Errorf("session fix still phrased as a permission removal: %q", got)
	}
	if !strings.Contains(got, "alice@CORP.LOCAL") || !strings.Contains(got, "WKS-01.CORP.LOCAL") {
		t.Errorf("session fix does not name both the account and the machine: %q", got)
	}
}

// Everything else keeps naming the concrete change.
func TestRemediationCoversTheEdgesThatAppearInReports(t *testing.T) {
	for _, e := range []parse.EdgeType{
		parse.AdminTo, parse.CanRDP, parse.CanPSRemote, parse.MemberOf,
		parse.DCSync, parse.AllowedToDelegate, parse.Contains, parse.GPLink,
		parse.GenericAll, parse.WriteDacl,
	} {
		got := Remediation(e, "", "A@CORP.LOCAL", "B@CORP.LOCAL")
		if got == "" {
			t.Errorf("%s has no remediation sentence", e)
		}
		if !strings.HasSuffix(strings.TrimSpace(got), ".") {
			t.Errorf("%s remediation is not a sentence: %q", e, got)
		}
		if !strings.Contains(got, "A@CORP.LOCAL") {
			t.Errorf("%s remediation does not name the principal: %q", e, got)
		}
	}
}
