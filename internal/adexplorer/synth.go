package adexplorer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"
)

// This file writes a valid AD Explorer snapshot. It exists for two reasons:
//
//  1. Tests need real binary input. Asserting against a fixture we cannot
//     regenerate is how a parser rots.
//  2. `harbinger check` runs the .dat path end-to-end on the user's own
//     machine, so an MSP can prove the binary reads snapshots correctly before
//     pointing it at a client's directory.

// SynthWriteFile writes a small, self-consistent synthetic snapshot to path.
// The directory it describes contains a known attack path:
//
//	HELPDESK@CORP.LOCAL --GenericAll--> TIER1ADMINS --MemberOf--> DOMAIN ADMINS
//
// plus a service account holding both replication rights on the domain, which
// must be collapsed into a single DCSync edge.
func SynthWriteFile(path string) error {
	b, err := SynthBytes()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// SynthBytes builds the synthetic snapshot in memory.
func SynthBytes() ([]byte, error) {
	const (
		domSID = "S-1-5-21-1004336348-1177238915-682003330"
		dnDom  = "DC=CORP,DC=LOCAL"
	)
	sw := newSnapWriter("DC01.CORP.LOCAL", "harbinger synthetic snapshot")

	// --- domain ---
	domSD := buildSD(domSID+"-512", []aceSpec{
		// A service account with both halves of replication => DCSync.
		{mask: rightDSControlAccess, guid: guidGetChanges, sid: domSID + "-1107"},
		{mask: rightDSControlAccess, guid: guidGetChangesAll, sid: domSID + "-1107"},
	})
	sw.object(map[string]any{
		"distinguishedName":    dnDom,
		"objectClass":          []string{"top", "domain", "domainDNS"},
		"objectSid":            sidBytes(domSID),
		"objectGUID":           guidBytes("11111111-1111-1111-1111-111111111111"),
		"name":                 "CORP",
		"nTSecurityDescriptor": sdVal(domSD),
	})

	// --- Domain Admins, with Tier1Admins nested inside it ---
	sw.object(map[string]any{
		"distinguishedName": "CN=Domain Admins,CN=Users," + dnDom,
		"objectClass":       []string{"top", "group"},
		"objectSid":         sidBytes(domSID + "-512"),
		"objectGUID":        guidBytes("22222222-2222-2222-2222-222222222222"),
		"sAMAccountName":    "Domain Admins",
		"adminCount":        uint32(1),
		"member":            []string{"CN=Tier1Admins,OU=Groups," + dnDom},
	})

	// Tier1Admins: helpdesk holds GenericAll over it — the escalation.
	t1SD := buildSD(domSID+"-512", []aceSpec{
		{mask: rightGenericAll, sid: domSID + "-1105"},
	})
	sw.object(map[string]any{
		"distinguishedName":    "CN=Tier1Admins,OU=Groups," + dnDom,
		"objectClass":          []string{"top", "group"},
		"objectSid":            sidBytes(domSID + "-1106"),
		"objectGUID":           guidBytes("33333333-3333-3333-3333-333333333333"),
		"sAMAccountName":       "Tier1Admins",
		"nTSecurityDescriptor": sdVal(t1SD),
	})

	// --- the low-privilege user that starts the path ---
	sw.object(map[string]any{
		"distinguishedName":  "CN=helpdesk,OU=Staff," + dnDom,
		"objectClass":        []string{"top", "person", "organizationalPerson", "user"},
		"objectSid":          sidBytes(domSID + "-1105"),
		"objectGUID":         guidBytes("44444444-4444-4444-4444-444444444444"),
		"sAMAccountName":     "helpdesk",
		"userAccountControl": uint32(512),
		"primaryGroupID":     uint32(513),
	})

	// --- the replication service account ---
	sw.object(map[string]any{
		"distinguishedName":        "CN=svc-backup,OU=Service," + dnDom,
		"objectClass":              []string{"top", "person", "organizationalPerson", "user"},
		"objectSid":                sidBytes(domSID + "-1107"),
		"objectGUID":               guidBytes("55555555-5555-5555-5555-555555555555"),
		"sAMAccountName":           "svc-backup",
		"userAccountControl":       uint32(512),
		"servicePrincipalName":     []string{"MSSQLSvc/sql01.corp.local:1433"},
		"primaryGroupID":           uint32(513),
		"msDS-AllowedToDelegateTo": []string{"CIFS/DC01.corp.local"},
	})

	// --- a domain controller ---
	sw.object(map[string]any{
		"distinguishedName":  "CN=DC01,OU=Domain Controllers," + dnDom,
		"objectClass":        []string{"top", "computer"},
		"objectSid":          sidBytes(domSID + "-1000"),
		"objectGUID":         guidBytes("66666666-6666-6666-6666-666666666666"),
		"sAMAccountName":     "DC01$",
		"dNSHostName":        "DC01.corp.local",
		"userAccountControl": uint32(0x2000 | 0x80000), // SERVER_TRUST + unconstrained
		"primaryGroupID":     uint32(516),
	})

	// --- an OU holding the staff, linked to a GPO ---
	sw.object(map[string]any{
		"distinguishedName": "OU=Staff," + dnDom,
		"objectClass":       []string{"top", "organizationalUnit"},
		"objectGUID":        guidBytes("77777777-7777-7777-7777-777777777777"),
		"name":              "Staff",
		"gPLink":            "[LDAP://CN={88888888-8888-8888-8888-888888888888},CN=Policies,CN=System," + dnDom + ";0]",
	})
	sw.object(map[string]any{
		"distinguishedName": "CN={88888888-8888-8888-8888-888888888888},CN=Policies,CN=System," + dnDom,
		"objectClass":       []string{"top", "container", "groupPolicyContainer"},
		"objectGUID":        guidBytes("88888888-8888-8888-8888-888888888888"),
		"name":              "Workstation Baseline",
	})

	return sw.finish()
}

// ---- snapshot writer ----

type snapWriter struct {
	server, desc string
	propNames    []string
	propTypes    []uint32
	propIndex    map[string]int
	objects      [][]byte
}

func newSnapWriter(server, desc string) *snapWriter {
	return &snapWriter{server: server, desc: desc, propIndex: map[string]int{}}
}

// adsTypeFor picks the on-disk type for an attribute from the Go value used to
// express it, mirroring the real schema closely enough to exercise every branch
// of the decoder.
func adsTypeFor(name string, v any) uint32 {
	switch name {
	case "objectClass":
		return adsObjectClass
	case "nTSecurityDescriptor", "msDS-GroupMSAMembership", "msDS-AllowedToActOnBehalfOfOtherIdentity":
		return adsNTSecurityDescript
	case "distinguishedName", "member":
		return adsDNString
	}
	switch v.(type) {
	case []byte:
		return adsOctetString
	case uint32:
		return adsInteger
	case int64:
		return adsLargeInteger
	}
	return adsCaseIgnoreString
}

func (w *snapWriter) prop(name string, v any) int {
	if i, ok := w.propIndex[strings.ToLower(name)]; ok {
		return i
	}
	i := len(w.propNames)
	w.propNames = append(w.propNames, name)
	w.propTypes = append(w.propTypes, adsTypeFor(name, v))
	w.propIndex[strings.ToLower(name)] = i
	return i
}

// object appends one directory object. Attributes are emitted in a stable
// (sorted) order so the produced file is byte-for-byte reproducible.
func (w *snapWriter) object(attrs map[string]any) {
	names := make([]string, 0, len(attrs))
	for k := range attrs {
		names = append(names, k)
	}
	sortStrings(names)

	type blob struct {
		idx  int
		data []byte
	}
	blobs := make([]blob, 0, len(names))
	for _, n := range names {
		idx := w.prop(n, attrs[n])
		blobs = append(blobs, blob{idx: idx, data: encodeValue(w.propTypes[idx], attrs[n])})
	}

	tableSize := len(blobs)
	headerLen := 8 + tableSize*8
	var body bytes.Buffer
	offs := make([]int32, tableSize)
	at := headerLen
	for i, b := range blobs {
		offs[i] = int32(at)
		body.Write(b.data)
		at += len(b.data)
	}

	var out bytes.Buffer
	u32(&out, uint32(headerLen+body.Len()))
	u32(&out, uint32(tableSize))
	for i, b := range blobs {
		u32(&out, uint32(b.idx))
		u32(&out, uint32(offs[i]))
	}
	out.Write(body.Bytes())
	w.objects = append(w.objects, out.Bytes())
}

func (w *snapWriter) finish() ([]byte, error) {
	var out bytes.Buffer

	objBytes := 0
	for _, o := range w.objects {
		objBytes += len(o)
	}
	metaOffset := uint64(headerSize + objBytes)

	// header
	out.WriteString(sig)
	u32(&out, 0) // marker
	u64(&out, 0) // filetime — zero keeps the output reproducible
	out.Write(fixedWide(w.desc, 260))
	out.Write(fixedWide(w.server, 260))
	u32(&out, uint32(len(w.objects)))
	u32(&out, uint32(len(w.propNames)))
	u64(&out, metaOffset)
	u64(&out, metaOffset) // treeview offset — unused by the reader
	if out.Len() != headerSize {
		return nil, fmt.Errorf("internal: synthetic header is %d bytes, want %d", out.Len(), headerSize)
	}

	for _, o := range w.objects {
		out.Write(o)
	}

	// metadata: properties, then empty class and rights tables
	u32(&out, uint32(len(w.propNames)))
	for i, n := range w.propNames {
		nb := wideNul(n)
		u32(&out, uint32(len(nb)))
		out.Write(nb)
		u32(&out, 0) // unk1
		u32(&out, w.propTypes[i])
		dn := wideNul("CN=" + n + ",CN=Schema,CN=Configuration,DC=CORP,DC=LOCAL")
		u32(&out, uint32(len(dn)))
		out.Write(dn)
		out.Write(make([]byte, 16+16+4))
	}
	u32(&out, 0) // numClasses
	u32(&out, 0) // numRights

	return out.Bytes(), nil
}

// encodeValue serializes one attribute's values in the on-disk layout for its type.
func encodeValue(adsType uint32, v any) []byte {
	var out bytes.Buffer
	switch adsType {
	case adsDNString, adsCaseExactString, adsCaseIgnoreString, adsPrintableString, adsNumericString, adsObjectClass:
		vals := toStrings(v)
		u32(&out, uint32(len(vals)))
		// Offsets are relative to the start of this blob.
		base := 4 + 4*len(vals)
		off := base
		encoded := make([][]byte, len(vals))
		for i, s := range vals {
			encoded[i] = wideNul(s)
		}
		for i := range vals {
			u32(&out, uint32(off))
			off += len(encoded[i])
		}
		for _, e := range encoded {
			out.Write(e)
		}
	case adsOctetString:
		vals := toByteSlices(v)
		u32(&out, uint32(len(vals)))
		for _, b := range vals {
			u32(&out, uint32(len(b)))
		}
		for _, b := range vals {
			out.Write(b)
		}
	case adsNTSecurityDescript:
		vals := toByteSlices(v)
		u32(&out, uint32(len(vals)))
		for _, b := range vals {
			u32(&out, uint32(len(b)))
			out.Write(b)
		}
	case adsBoolean, adsInteger:
		u32(&out, 1)
		u32(&out, v.(uint32))
	case adsLargeInteger:
		u32(&out, 1)
		u64(&out, uint64(v.(int64)))
	}
	return out.Bytes()
}

// ---- security descriptor construction ----

type aceSpec struct {
	mask uint32
	guid string // empty => plain ACCESS_ALLOWED_ACE
	sid  string
}

// buildSD assembles a self-relative security descriptor with an owner and DACL.
func buildSD(owner string, aces []aceSpec) []byte {
	var acl bytes.Buffer
	for _, a := range aces {
		sb := sidBytes(a.sid)
		var ace bytes.Buffer
		if a.guid == "" {
			size := 8 + len(sb)
			ace.WriteByte(aceAccessAllowed)
			ace.WriteByte(0)
			u16(&ace, uint16(size))
			u32(&ace, a.mask)
			ace.Write(sb)
		} else {
			size := 8 + 4 + 16 + len(sb)
			ace.WriteByte(aceAccessAllowedObject)
			ace.WriteByte(0)
			u16(&ace, uint16(size))
			u32(&ace, a.mask)
			u32(&ace, aceObjectTypePresent)
			ace.Write(guidBytes(a.guid))
			ace.Write(sb)
		}
		acl.Write(ace.Bytes())
	}

	aclSize := 8 + acl.Len()
	var aclOut bytes.Buffer
	aclOut.WriteByte(4) // ACL_REVISION_DS
	aclOut.WriteByte(0)
	u16(&aclOut, uint16(aclSize))
	u16(&aclOut, uint16(len(aces)))
	u16(&aclOut, 0)
	aclOut.Write(acl.Bytes())

	ownerB := sidBytes(owner)
	const hdr = 20
	offDacl := hdr
	offOwner := hdr + aclOut.Len()

	var sd bytes.Buffer
	sd.WriteByte(1) // revision
	sd.WriteByte(0)
	u16(&sd, 0x8004) // SE_SELF_RELATIVE | SE_DACL_PRESENT
	u32(&sd, uint32(offOwner))
	u32(&sd, 0) // group
	u32(&sd, 0) // sacl
	u32(&sd, uint32(offDacl))
	sd.Write(aclOut.Bytes())
	sd.Write(ownerB)
	return sd.Bytes()
}

func sdVal(b []byte) []byte { return b }

// sidBytes encodes "S-1-5-21-a-b-c-rid" into its binary form.
func sidBytes(s string) []byte {
	parts := strings.Split(strings.TrimPrefix(strings.ToUpper(s), "S-"), "-")
	if len(parts) < 2 {
		return nil
	}
	rev, _ := strconv.Atoi(parts[0])
	auth, _ := strconv.ParseUint(parts[1], 10, 64)
	subs := parts[2:]

	var out bytes.Buffer
	out.WriteByte(byte(rev))
	out.WriteByte(byte(len(subs)))
	for i := 5; i >= 0; i-- {
		out.WriteByte(byte(auth >> (8 * uint(i))))
	}
	for _, s := range subs {
		v, _ := strconv.ParseUint(s, 10, 32)
		u32(&out, uint32(v))
	}
	return out.Bytes()
}

// guidBytes encodes a GUID string into its little-endian binary form.
func guidBytes(g string) []byte {
	h := strings.ReplaceAll(strings.TrimSpace(g), "-", "")
	if len(h) != 32 {
		return make([]byte, 16)
	}
	raw := make([]byte, 16)
	for i := 0; i < 16; i++ {
		v, _ := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		raw[i] = byte(v)
	}
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}

// ---- byte helpers ----

func u16(b *bytes.Buffer, v uint16) { _ = binary.Write(b, binary.LittleEndian, v) }
func u32(b *bytes.Buffer, v uint32) { _ = binary.Write(b, binary.LittleEndian, v) }
func u64(b *bytes.Buffer, v uint64) { _ = binary.Write(b, binary.LittleEndian, v) }

func wideNul(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2+2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return append(out, 0, 0)
}

func fixedWide(s string, chars int) []byte {
	units := utf16.Encode([]rune(s))
	if len(units) > chars-1 {
		units = units[:chars-1]
	}
	out := make([]byte, chars*2)
	for i, u := range units {
		out[i*2] = byte(u)
		out[i*2+1] = byte(u >> 8)
	}
	return out
}

func toStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	}
	return nil
}

func toByteSlices(v any) [][]byte {
	switch t := v.(type) {
	case []byte:
		return [][]byte{t}
	case [][]byte:
		return t
	}
	return nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
