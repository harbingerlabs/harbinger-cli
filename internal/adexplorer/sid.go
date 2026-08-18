package adexplorer

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// SIDString formats a binary SID as S-1-5-21-… . It returns "" for anything
// that is not a well-formed SID, so callers can treat "" as "not a principal"
// rather than propagating a garbage identifier into the graph.
func SIDString(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	rev := b[0]
	subCount := int(b[1])
	if rev != 1 || subCount == 0 || subCount > 15 {
		return ""
	}
	if len(b) < 8+subCount*4 {
		return ""
	}
	// IdentifierAuthority is 6 bytes, big-endian.
	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", rev, auth)
	for i := 0; i < subCount; i++ {
		v := binary.LittleEndian.Uint32(b[8+i*4 : 12+i*4])
		fmt.Fprintf(&sb, "-%d", v)
	}
	return sb.String()
}

// sidLen returns the encoded length of the SID at the start of b, or 0.
func sidLen(b []byte) int {
	if len(b) < 8 {
		return 0
	}
	n := 8 + int(b[1])*4
	if b[0] != 1 || int(b[1]) > 15 || n > len(b) {
		return 0
	}
	return n
}

// GUIDString formats a 16-byte little-endian GUID the way AD and BloodHound do
// (uppercase, no braces).
func GUIDString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return strings.ToUpper(fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16]))
}

// RID returns the trailing relative identifier of a domain SID, or "".
func RID(sid string) string {
	if !strings.HasPrefix(strings.ToUpper(sid), "S-1-5-21-") {
		return ""
	}
	if i := strings.LastIndex(sid, "-"); i > 0 && i < len(sid)-1 {
		return sid[i+1:]
	}
	return ""
}

// DomainPart converts a distinguished name into its DNS domain
// ("CN=x,OU=y,DC=corp,DC=local" -> "CORP.LOCAL"). Returns "" if there is no DC=.
func DomainPart(dn string) string {
	var parts []string
	for _, seg := range splitDN(dn) {
		if len(seg) > 3 && strings.EqualFold(seg[:3], "DC=") {
			parts = append(parts, seg[3:])
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.ToUpper(strings.Join(parts, "."))
}

// splitDN splits a distinguished name on unescaped commas.
func splitDN(dn string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range dn {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ',':
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}
