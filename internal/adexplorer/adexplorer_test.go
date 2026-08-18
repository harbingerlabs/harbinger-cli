package adexplorer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

func writeSynth(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "snapshot.dat")
	if err := SynthWriteFile(p); err != nil {
		t.Fatalf("writing synthetic snapshot: %v", err)
	}
	return p
}

func TestSIDRoundTrip(t *testing.T) {
	for _, s := range []string{
		"S-1-5-21-1004336348-1177238915-682003330-512",
		"S-1-5-32-544",
		"S-1-1-0",
		"S-1-5-18",
	} {
		if got := SIDString(sidBytes(s)); got != s {
			t.Errorf("SID round trip: got %q want %q", got, s)
		}
	}
}

func TestGUIDRoundTrip(t *testing.T) {
	const g = "5B47D60F-6090-40B2-9F37-2A4DE88F3063"
	if got := GUIDString(guidBytes(g)); got != g {
		t.Errorf("GUID round trip: got %q want %q", got, g)
	}
}

func TestSIDStringRejectsGarbage(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":         {},
		"short":         {1, 2, 3},
		"bad revision":  {9, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0},
		"too many subs": {1, 99, 0, 0, 0, 0, 0, 5},
	} {
		if got := SIDString(b); got != "" {
			t.Errorf("%s: expected empty, got %q", name, got)
		}
	}
}

func TestOpenSynthetic(t *testing.T) {
	s, err := Open(writeSynth(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if s.Server != "DC01.CORP.LOCAL" {
		t.Errorf("server = %q", s.Server)
	}
	if s.Len() != 8 {
		t.Errorf("object count = %d, want 8", s.Len())
	}

	o, err := s.Object(0)
	if err != nil {
		t.Fatalf("Object(0): %v", err)
	}
	if dn := o.Str("distinguishedName"); dn != "DC=CORP,DC=LOCAL" {
		t.Errorf("dn = %q", dn)
	}
	// Case-insensitive lookup, as LDAP is.
	if dn := o.Str("DISTINGUISHEDNAME"); dn != "DC=CORP,DC=LOCAL" {
		t.Errorf("case-insensitive lookup failed: %q", dn)
	}
	classes := o.Strs("objectClass")
	if len(classes) != 3 || classes[2] != "domainDNS" {
		t.Errorf("objectClass = %v", classes)
	}
}

func TestIngestBuildsExpectedGraph(t *testing.T) {
	g, rep, err := Ingest(writeSynth(t))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	const dom = "S-1-5-21-1004336348-1177238915-682003330"
	want := map[string]parse.Kind{
		dom:           parse.KindDomain,
		dom + "-512":  parse.KindGroup, // Domain Admins
		dom + "-1106": parse.KindGroup, // Tier1Admins
		dom + "-1105": parse.KindUser,  // helpdesk
		dom + "-1107": parse.KindUser,  // svc-backup
		dom + "-1000": parse.KindComputer,
	}
	for id, kind := range want {
		n := g.Node(id)
		if n == nil {
			t.Fatalf("missing node %s", id)
		}
		if n.Kind != kind {
			t.Errorf("%s: kind = %s, want %s", id, n.Kind, kind)
		}
	}

	if n := g.Node(dom + "-1105"); n.Name != "HELPDESK@CORP.LOCAL" {
		t.Errorf("helpdesk name = %q, want HELPDESK@CORP.LOCAL", n.Name)
	}
	if n := g.Node(dom + "-1000"); !n.IsDC || !n.Unconstr {
		t.Errorf("DC01: IsDC=%v Unconstr=%v, want both true", n.IsDC, n.Unconstr)
	}
	if n := g.Node(dom + "-1107"); !n.HasSPN {
		t.Error("svc-backup should be flagged as having an SPN")
	}

	// The whole point: ACL edges must come out of the security descriptor.
	if !hasEdge(g, dom+"-1105", dom+"-1106", parse.GenericAll) {
		t.Error("missing GenericAll: helpdesk -> Tier1Admins")
	}
	if !hasEdge(g, dom+"-1106", dom+"-512", parse.MemberOf) {
		t.Error("missing MemberOf: Tier1Admins -> Domain Admins")
	}
	// Both replication rights must collapse into one DCSync edge.
	if !hasEdge(g, dom+"-1107", dom, parse.GetChanges) || !hasEdge(g, dom+"-1107", dom, parse.GetChangesAll) {
		t.Error("missing replication rights on the domain")
	}
	if !hasEdge(g, dom+"-1107", dom, parse.DCSync) {
		t.Error("GetChanges + GetChangesAll should synthesize DCSync")
	}
	// primaryGroupID 516 makes the DC a member of Domain Controllers.
	if !hasEdge(g, dom+"-1000", dom+"-516", parse.MemberOf) {
		t.Error("missing primaryGroupID membership for the DC")
	}
	// Containment and GPO linkage.
	if !hasEdge(g, "77777777-7777-7777-7777-777777777777", dom+"-1105", parse.Contains) {
		t.Error("missing Contains: Staff OU -> helpdesk")
	}
	if !hasEdge(g, "88888888-8888-8888-8888-888888888888", "77777777-7777-7777-7777-777777777777", parse.GPLink) {
		t.Error("missing GPLink: GPO -> Staff OU")
	}
	// Constrained delegation resolved through the SPN's host.
	if !hasEdge(g, dom+"-1107", dom+"-1000", parse.AllowedToDelegate) {
		t.Error("missing AllowedToDelegate: svc-backup -> DC01")
	}

	// Owner of Tier1Admins is Domain Admins, which is a filtered noise source:
	// no Owns edge should be emitted from it.
	if hasEdge(g, dom+"-512", dom+"-1106", parse.Owns) {
		t.Error("Owns edge from Domain Admins should be filtered as noise")
	}

	// The report must declare what a snapshot cannot see.
	if rep.Modality == "" {
		t.Error("report modality not set")
	}
	if len(rep.Gaps) < 2 {
		t.Errorf("expected session and local-admin gaps to be declared, got %v", rep.Gaps)
	}
	joined := strings.ToLower(strings.Join(rep.Gaps, " "))
	if !strings.Contains(joined, "session") {
		t.Error("gaps must name the missing session collection")
	}
}

func hasEdge(g *parse.Graph, from, to string, t parse.EdgeType) bool {
	for _, e := range g.Out(from) {
		if strings.EqualFold(e.To, to) && e.Type == t {
			return true
		}
	}
	return false
}

// --- robustness: real exports are messy, and must never crash the tool ---

func TestMalformedInputsFailCleanly(t *testing.T) {
	dir := t.TempDir()
	good, err := SynthBytes()
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty file":           {},
		"short file":           []byte("win"),
		"wrong signature":      append([]byte("NOTASNAPSH"), make([]byte, 4096)...),
		"header only":          good[:headerSize],
		"truncated mid-object": good[:headerSize+16],
		"truncated at half":    good[:len(good)/2],
		"zeroed header":        make([]byte, 8192),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".dat")
			if err := os.WriteFile(p, body, 0o600); err != nil {
				t.Fatal(err)
			}
			// The contract is: an error, never a panic, never a hang.
			g, _, err := Ingest(p)
			if err == nil && g == nil {
				t.Fatal("returned neither a graph nor an error")
			}
			if err != nil && strings.TrimSpace(err.Error()) == "" {
				t.Fatal("returned an empty error message")
			}
		})
	}
}

// A snapshot whose bytes are randomly corrupted must still never panic. This is
// the property that matters for a tool a stranger runs on their own network.
func TestCorruptionNeverPanics(t *testing.T) {
	good, err := SynthBytes()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// Deterministic sweep: flip one byte at a time across the file.
	for i := 0; i < len(good); i += 37 {
		body := append([]byte(nil), good...)
		body[i] ^= 0xFF
		p := filepath.Join(dir, "fuzz.dat")
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on corrupted byte %d: %v", i, r)
				}
			}()
			_, _, _ = Ingest(p) // any outcome is fine except a panic
		}()
	}
}

func TestIsSnapshotDetection(t *testing.T) {
	p := writeSynth(t)
	if !IsSnapshot(p) {
		t.Error("synthetic snapshot not detected")
	}
	notSnap := filepath.Join(t.TempDir(), "export.json")
	if err := os.WriteFile(notSnap, []byte(`{"meta":{"type":"users"},"data":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if IsSnapshot(notSnap) {
		t.Error("JSON export misdetected as a snapshot")
	}
	if IsSnapshot(filepath.Join(t.TempDir(), "missing.dat")) {
		t.Error("missing file reported as a snapshot")
	}
}

func TestGPLinkParsing(t *testing.T) {
	in := "[LDAP://CN={AAA},CN=Policies,DC=x;0][LDAP://CN={BBB},CN=Policies,DC=x;1][LDAP://CN={CCC},CN=Policies,DC=x;2]"
	got := parseGPLink(in)
	// Flag 1 = link disabled, so BBB must be dropped; 2 = enforced, kept.
	want := []string{"CN={AAA},CN=Policies,DC=x", "CN={CCC},CN=Policies,DC=x"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("link %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDomainPartAndDNSplitting(t *testing.T) {
	if got := DomainPart("CN=a,OU=b,DC=corp,DC=local"); got != "CORP.LOCAL" {
		t.Errorf("DomainPart = %q", got)
	}
	if got := DomainPart("CN=a,OU=b"); got != "" {
		t.Errorf("DomainPart with no DC= should be empty, got %q", got)
	}
	// An escaped comma inside an RDN must not split the DN.
	segs := splitDN(`CN=Smith\, John,OU=Staff,DC=corp,DC=local`)
	if len(segs) != 4 || segs[0] != `CN=Smith, John` {
		t.Errorf("splitDN = %#v", segs)
	}
}

func TestMaskToEdges(t *testing.T) {
	cases := []struct {
		name string
		mask uint32
		guid string
		kind parse.Kind
		want parse.EdgeType
	}{
		{"generic all", rightGenericAll, "", parse.KindUser, parse.GenericAll},
		{"write dacl", rightWriteDACL, "", parse.KindUser, parse.WriteDacl},
		{"write owner", rightWriteOwner, "", parse.KindUser, parse.WriteOwner},
		{"force change password", rightDSControlAccess, guidForceChangePwd, parse.KindUser, parse.ForceChangePassword},
		{"get changes", rightDSControlAccess, guidGetChanges, parse.KindDomain, parse.GetChanges},
		{"all extended rights", rightDSControlAccess, "", parse.KindUser, parse.AllExtendedRights},
		{"add member", rightDSWriteProp, guidAttrMember, parse.KindGroup, parse.AddMember},
		{"write spn", rightDSWriteProp, guidAttrSPN, parse.KindUser, parse.WriteSPN},
		{"shadow creds", rightDSWriteProp, guidKeyCredentialLink, parse.KindUser, parse.AddKeyCredentialLink},
		{"rbcd", rightDSWriteProp, guidAllowedToAct, parse.KindComputer, parse.AllowedToAct},
		{"add self", rightDSSelf, guidAttrMember, parse.KindGroup, parse.AddSelf},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := maskToEdges(c.mask, c.guid, c.kind)
			for _, e := range got {
				if e == c.want {
					return
				}
			}
			t.Errorf("maskToEdges(%#x, %q) = %v, want to include %s", c.mask, c.guid, got, c.want)
		})
	}
	// A read-only mask must not produce a control edge.
	if got := maskToEdges(0x00000010, "", parse.KindUser); len(got) != 0 {
		t.Errorf("read-only mask produced %v", got)
	}
}

func TestNoiseSourceFiltering(t *testing.T) {
	for _, sid := range []string{
		"S-1-5-18", "S-1-5-10", "S-1-3-0", "S-1-5-32-544",
		"S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-519",
	} {
		if !isNoiseSource(sid) {
			t.Errorf("%s should be filtered as a noise source", sid)
		}
	}
	for _, sid := range []string{"S-1-5-21-1-2-3-1105", "S-1-5-11"} {
		if isNoiseSource(sid) {
			t.Errorf("%s should NOT be filtered", sid)
		}
	}
}

// A security descriptor is attacker-influenced data. Malformed offsets must be
// absorbed, not trusted.
func TestSecurityDescriptorRobustness(t *testing.T) {
	good := buildSD("S-1-5-21-1-2-3-512", []aceSpec{{mask: rightGenericAll, sid: "S-1-5-21-1-2-3-1105"}})
	if owner, edges := parseSecurityDescriptor(good, parse.KindGroup); owner == "" || len(edges) != 1 {
		t.Fatalf("baseline descriptor failed: owner=%q edges=%v", owner, edges)
	}
	for name, sd := range map[string][]byte{
		"empty":             {},
		"too short":         {1, 0, 4, 128},
		"bad revision":      append([]byte{9}, good[1:]...),
		"truncated":         good[:len(good)/2],
		"dacl past end":     withU32(good, 16, 0xFFFFFF),
		"owner past end":    withU32(good, 4, 0xFFFFFF),
		"negative-ish dacl": withU32(good, 16, 0x80000000),
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			_, _ = parseSecurityDescriptor(sd, parse.KindGroup)
		})
	}
}

func withU32(b []byte, off int, v uint32) []byte {
	out := append([]byte(nil), b...)
	if off+4 > len(out) {
		return out
	}
	out[off] = byte(v)
	out[off+1] = byte(v >> 8)
	out[off+2] = byte(v >> 16)
	out[off+3] = byte(v >> 24)
	return out
}

// Reproducibility: the same input must produce the same bytes, so that a
// customer and we can compare snapshots and checksums meaningfully.
func TestSynthIsDeterministic(t *testing.T) {
	a, err := SynthBytes()
	if err != nil {
		t.Fatal(err)
	}
	b, err := SynthBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("lengths differ: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("byte %d differs", i)
		}
	}
}
