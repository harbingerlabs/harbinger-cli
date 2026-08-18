package parse_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

// MSPs run older tooling than pentest firms do, so both the current BloodHound
// CE shape and the Legacy (pre-4.x / older SharpHound) shape have to load and
// produce the SAME graph. These fixtures encode the two shapes explicitly.

// Legacy: bare arrays for Members/Aces, "Right"/"PrincipalID" ACE keys,
// properties under "Properties" with an "objectsid" fallback.
const legacyGroups = `{
  "meta": {"type": "groups", "count": 2, "version": 3},
  "data": [
    {
      "ObjectIdentifier": "S-1-5-21-1-2-3-512",
      "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "highvalue": true, "domainsid": "S-1-5-21-1-2-3"},
      "Members": [{"ObjectIdentifier": "S-1-5-21-1-2-3-1106", "ObjectType": "Group"}],
      "Aces": [{"PrincipalID": "S-1-5-21-1-2-3-1105", "Right": "WriteDacl", "PrincipalType": "User"}]
    },
    {
      "ObjectIdentifier": "S-1-5-21-1-2-3-1106",
      "Properties": {"name": "TIER1ADMINS@CORP.LOCAL", "domainsid": "S-1-5-21-1-2-3"},
      "Members": [],
      "Aces": [{"PrincipalID": "S-1-5-21-1-2-3-1105", "Right": "GenericAll", "PrincipalType": "User"}]
    }
  ]
}`

const legacyUsers = `{
  "meta": {"type": "users", "count": 1, "version": 3},
  "data": [
    {
      "ObjectIdentifier": "S-1-5-21-1-2-3-1105",
      "Properties": {"name": "HELPDESK@CORP.LOCAL", "enabled": true, "domainsid": "S-1-5-21-1-2-3"},
      "Aces": []
    }
  ]
}`

const legacyDomains = `{
  "meta": {"type": "domains", "count": 1, "version": 3},
  "data": [
    {
      "ObjectIdentifier": "S-1-5-21-1-2-3",
      "Properties": {"name": "CORP.LOCAL", "domainsid": "S-1-5-21-1-2-3"},
      "Aces": [
        {"PrincipalID": "S-1-5-21-1-2-3-1107", "Right": "GetChanges", "PrincipalType": "User"},
        {"PrincipalID": "S-1-5-21-1-2-3-1107", "Right": "GetChangesAll", "PrincipalType": "User"}
      ],
      "Links": [],
      "ChildObjects": []
    }
  ]
}`

// CE: Members/ChildObjects wrapped in a {"Collected":..,"Results":[..]} envelope,
// ACE keys "PrincipalSID"/"RightName", meta version 5+.
const ceGroups = `{
  "meta": {"methods": 46067, "type": "groups", "count": 2, "version": 6},
  "data": [
    {
      "ObjectIdentifier": "S-1-5-21-1-2-3-512",
      "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "highvalue": true, "domainsid": "S-1-5-21-1-2-3"},
      "Members": {"Collected": true, "FailureReason": null, "Results": [{"ObjectIdentifier": "S-1-5-21-1-2-3-1106", "ObjectType": "Group"}]},
      "Aces": [{"PrincipalSID": "S-1-5-21-1-2-3-1105", "RightName": "WriteDacl", "IsInherited": false, "PrincipalType": "User"}]
    },
    {
      "ObjectIdentifier": "S-1-5-21-1-2-3-1106",
      "Properties": {"name": "TIER1ADMINS@CORP.LOCAL", "domainsid": "S-1-5-21-1-2-3"},
      "Members": {"Collected": true, "FailureReason": null, "Results": []},
      "Aces": [{"PrincipalSID": "S-1-5-21-1-2-3-1105", "RightName": "GenericAll", "IsInherited": false, "PrincipalType": "User"}]
    }
  ]
}`

const ceUsers = `{
  "meta": {"methods": 46067, "type": "users", "count": 1, "version": 6},
  "data": [
    {
      "ObjectIdentifier": "S-1-5-21-1-2-3-1105",
      "Properties": {"name": "HELPDESK@CORP.LOCAL", "enabled": true, "domainsid": "S-1-5-21-1-2-3"},
      "Aces": [],
      "AllowedToDelegate": [],
      "HasSIDHistory": []
    }
  ]
}`

const ceDomains = `{
  "meta": {"methods": 46067, "type": "domains", "count": 1, "version": 6},
  "data": [
    {
      "ObjectIdentifier": "S-1-5-21-1-2-3",
      "Properties": {"name": "CORP.LOCAL", "domainsid": "S-1-5-21-1-2-3"},
      "Aces": [
        {"PrincipalSID": "S-1-5-21-1-2-3-1107", "RightName": "GetChanges", "IsInherited": false, "PrincipalType": "User"},
        {"PrincipalSID": "S-1-5-21-1-2-3-1107", "RightName": "GetChangesAll", "IsInherited": false, "PrincipalType": "User"}
      ],
      "Links": {"Collected": true, "Results": []},
      "ChildObjects": {"Collected": true, "Results": []}
    }
  ]
}`

func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func edgeSet(g *parse.Graph) map[string]bool {
	out := map[string]bool{}
	for _, e := range g.Edges {
		out[strings.ToUpper(e.From)+"|"+strings.ToUpper(e.To)+"|"+string(e.Type)] = true
	}
	return out
}

// The core promise: an MSP on old tooling and a pentest firm on new tooling get
// the same answer from the same directory.
func TestLegacyAndCEProduceIdenticalGraphs(t *testing.T) {
	legacy := writeFixture(t, map[string]string{
		"groups.json": legacyGroups, "users.json": legacyUsers, "domains.json": legacyDomains,
	})
	ce := writeFixture(t, map[string]string{
		"groups.json": ceGroups, "users.json": ceUsers, "domains.json": ceDomains,
	})

	gl, repL, err := parse.Ingest(legacy)
	if err != nil {
		t.Fatalf("legacy ingest: %v", err)
	}
	gc, repC, err := parse.Ingest(ce)
	if err != nil {
		t.Fatalf("CE ingest: %v", err)
	}

	if len(gl.Nodes) != len(gc.Nodes) {
		t.Errorf("node count differs: legacy %d, CE %d", len(gl.Nodes), len(gc.Nodes))
	}
	el, ec := edgeSet(gl), edgeSet(gc)
	for k := range el {
		if !ec[k] {
			t.Errorf("edge %s present in Legacy but missing from CE", k)
		}
	}
	for k := range ec {
		if !el[k] {
			t.Errorf("edge %s present in CE but missing from Legacy", k)
		}
	}

	// And the edges we actually expect are there, in both.
	for name, g := range map[string]*parse.Graph{"legacy": gl, "ce": gc} {
		e := edgeSet(g)
		for _, want := range []string{
			"S-1-5-21-1-2-3-1105|S-1-5-21-1-2-3-1106|GenericAll",
			"S-1-5-21-1-2-3-1105|S-1-5-21-1-2-3-512|WriteDacl",
			"S-1-5-21-1-2-3-1106|S-1-5-21-1-2-3-512|MemberOf",
			"S-1-5-21-1-2-3-1107|S-1-5-21-1-2-3|DCSync",
		} {
			if !e[want] {
				t.Errorf("%s: missing edge %s", name, want)
			}
		}
	}

	if repL.Counts[parse.KindGroup] != 2 || repC.Counts[parse.KindGroup] != 2 {
		t.Errorf("group counts: legacy %d, CE %d", repL.Counts[parse.KindGroup], repC.Counts[parse.KindGroup])
	}
}

// Real exports are partial, stale and inconsistent. None of that may crash.
func TestMessyRealWorldExports(t *testing.T) {
	cases := map[string]map[string]string{
		"dangling ACE principal": {"groups.json": `{"meta":{"type":"groups"},"data":[
			{"ObjectIdentifier":"S-1-5-21-1-2-3-512","Properties":{"name":"DA@CORP"},
			 "Aces":[{"PrincipalSID":"S-1-5-21-9-9-9-1234","RightName":"GenericAll"}]}]}`},
		"member not collected": {"groups.json": `{"meta":{"type":"groups"},"data":[
			{"ObjectIdentifier":"S-1-5-21-1-2-3-512","Properties":{"name":"DA@CORP"},
			 "Members":{"Collected":false,"FailureReason":"Access denied","Results":null}}]}`},
		"null data array": {"users.json": `{"meta":{"type":"users"},"data":null}`},
		"missing meta block": {"users.json": `{"data":[
			{"ObjectIdentifier":"S-1-5-21-1-2-3-1105","Properties":{"name":"X@CORP"}}]}`},
		"unknown edge type": {"groups.json": `{"meta":{"type":"groups"},"data":[
			{"ObjectIdentifier":"S-1-5-21-1-2-3-512","Properties":{"name":"DA@CORP"},
			 "Aces":[{"PrincipalSID":"S-1-5-21-1-2-3-1105","RightName":"SomeEdgeInventedIn2027"}]}]}`},
		"object with no identifier": {"users.json": `{"meta":{"type":"users"},"data":[
			{"Properties":{"name":"ORPHAN"}},
			{"ObjectIdentifier":"S-1-5-21-1-2-3-1105","Properties":{"name":"X@CORP"}}]}`},
		"string booleans": {"users.json": `{"meta":{"type":"users"},"data":[
			{"ObjectIdentifier":"S-1-5-21-1-2-3-1105","Properties":{"name":"X@CORP","enabled":"true","admincount":"false"}}]}`},
		"self-referencing edge": {"groups.json": `{"meta":{"type":"groups"},"data":[
			{"ObjectIdentifier":"S-1-5-21-1-2-3-512","Properties":{"name":"DA@CORP"},
			 "Members":{"Results":[{"ObjectIdentifier":"S-1-5-21-1-2-3-512"}]}}]}`},
		"20 year old cruft": {"users.json": `{"meta":{"type":"users","version":1},"data":[
			{"ObjectIdentifier":"S-1-5-21-1-2-3-1105","Properties":{"name":"X@CORP",
			 "whencreated":915148800,"pwdlastset":-1,"lastlogon":0,"description":null}}]}`},
	}

	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %s: %v", name, r)
				}
			}()
			dir := writeFixture(t, files)
			g, rep, err := parse.Ingest(dir)
			if err != nil {
				// An error is acceptable, but it must be actionable prose.
				if len(err.Error()) < 10 {
					t.Fatalf("unhelpful error: %q", err)
				}
				return
			}
			if g == nil || rep == nil {
				t.Fatal("nil result without an error")
			}
		})
	}
}

// A dangling ACE must create a tolerated stub, be counted, and be rendered with
// a name a human can act on rather than a raw SID.
func TestDanglingPrincipalsAreLabelled(t *testing.T) {
	dir := writeFixture(t, map[string]string{"groups.json": `{"meta":{"type":"groups"},"data":[
		{"ObjectIdentifier":"S-1-5-21-1-2-3-512","Properties":{"name":"DA@CORP"},
		 "Aces":[{"PrincipalSID":"S-1-5-21-1-2-3-519","RightName":"GenericAll"},
		         {"PrincipalSID":"S-1-5-21-1-2-3-4242","RightName":"WriteDacl"}]}]}`})

	g, rep, err := parse.Ingest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Dangling == 0 {
		t.Error("dangling references were not counted")
	}
	// A well-known RID resolves to its real name even though it was not collected.
	if got := parse.DisplayName(g.Node("S-1-5-21-1-2-3-519")); !strings.Contains(got, "Enterprise Admins") {
		t.Errorf("well-known dangling SID rendered as %q", got)
	}
	// An unknown SID is labelled as unresolved, never printed bare.
	got := parse.DisplayName(g.Node("S-1-5-21-1-2-3-4242"))
	if !strings.Contains(strings.ToLower(got), "unresolved") {
		t.Errorf("unknown dangling SID rendered as %q, want an 'unresolved' label", got)
	}
	if got == "S-1-5-21-1-2-3-4242" {
		t.Error("raw SID leaked into the display name")
	}
}

func TestGapsAreDeclared(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"users.json": ceUsers, "groups.json": ceGroups, "domains.json": ceDomains,
	})
	_, rep, err := parse.Ingest(dir)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.ToLower(strings.Join(rep.Gaps, " "))
	// This fixture has no sessions and no computers; both must be declared, so
	// that "no path found" is never read as safety.
	if !strings.Contains(joined, "session") {
		t.Errorf("missing session gap; gaps = %v", rep.Gaps)
	}
	if !strings.Contains(joined, "computer") {
		t.Errorf("missing computer gap; gaps = %v", rep.Gaps)
	}
	if rep.Modality == "" {
		t.Error("modality not recorded")
	}
}
