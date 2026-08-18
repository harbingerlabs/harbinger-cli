package adexplorer

import (
	"encoding/binary"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

// This file turns an nTSecurityDescriptor into attack edges. It is the reason a
// snapshot is worth analyzing at all: group membership alone finds almost
// nothing, while the DACL is where GenericAll / WriteDacl / DCSync live.
//
// The mask -> edge mapping mirrors BloodHound's documented ACL semantics so
// that a snapshot-derived graph and a SharpHound-derived graph are comparable.

// Access mask bits (winnt.h + iads.h ADS_RIGHTS_ENUM).
const (
	rightDSCreateChild   = 0x00000001
	rightDSDeleteChild   = 0x00000002
	rightDSSelf          = 0x00000008
	rightDSWriteProp     = 0x00000020
	rightDSControlAccess = 0x00000100
	rightWriteDACL       = 0x00040000
	rightWriteOwner      = 0x00080000
	rightGenericAll      = 0x10000000
	rightGenericWrite    = 0x40000000
	rightFullControl     = 0x000F01FF
)

// ACE types (winnt.h).
const (
	aceAccessAllowed       = 0x00
	aceAccessAllowedObject = 0x05
)

// ACE flags.
const (
	aceInheritOnly = 0x08
)

// Object-ACE flags.
const (
	aceObjectTypePresent          = 0x01
	aceInheritedObjectTypePresent = 0x02
)

// Extended-right and attribute schema GUIDs that turn a generic mask into a
// specific, named attack primitive.
const (
	guidGetChanges         = "1131F6AA-9C07-11D1-F79F-00C04FC2DCD2"
	guidGetChangesAll      = "1131F6AD-9C07-11D1-F79F-00C04FC2DCD2"
	guidGetChangesFiltered = "89E95B76-444D-4C62-991A-0FACBEDA640C"
	guidForceChangePwd     = "00299570-246D-11D0-A768-00AA006E0529"
	guidAttrMember         = "BF9679C0-0DE6-11D0-A285-00AA003049E2"
	guidAttrSPN            = "F3A64788-5306-11D1-A9C5-0000F80367C1"
	guidKeyCredentialLink  = "5B47D60F-6090-40B2-9F37-2A4DE88F3063"
	guidAllowedToAct       = "3F78C3E5-F79A-46BD-A0B8-9D18116DDC79"
	guidLAPSPassword       = "C48784FB-9DA6-4D9B-B2E1-3B26E7E0D5E3" // ms-Mcs-AdmPwd is schema-generated; matched by name elsewhere
	guidGMSAPassword       = "888EEDD6-CE04-DF40-B462-B8A50E41BA38"
	guidAllGuid            = "00000000-0000-0000-0000-000000000000"
)

// noiseSIDs are principals whose control is already implied by Tier Zero
// membership, or that are not real principals at all. Emitting edges from them
// buries the report in millions of trivially-true rows. BloodHound applies the
// same reduction; we make it explicit and reversible.
var noiseSIDs = map[string]bool{
	"S-1-3-0":  true, // CREATOR OWNER
	"S-1-5-10": true, // SELF
	"S-1-5-18": true, // LOCAL SYSTEM
	"S-1-5-9":  true, // ENTERPRISE DOMAIN CONTROLLERS
}

// noiseRIDs: already-Tier-Zero groups. Control edges *from* them are noise;
// paths *to* them are exactly what we are looking for, so this only filters the
// source side.
var noiseRIDs = map[string]bool{
	"512": true, // Domain Admins
	"518": true, // Schema Admins
	"519": true, // Enterprise Admins
	"516": true, // Domain Controllers
	"498": true, // Enterprise Read-only Domain Controllers
}

// isNoiseSource reports whether ACEs granted to this principal should be dropped.
func isNoiseSource(sid string) bool {
	u := strings.ToUpper(sid)
	if noiseSIDs[u] {
		return true
	}
	if u == "S-1-5-32-544" { // BUILTIN\Administrators
		return true
	}
	return noiseRIDs[RID(u)]
}

// aclEdge is one derived control relationship.
type aclEdge struct {
	From string
	Type parse.EdgeType
}

// parseSecurityDescriptor extracts the owner SID and the DACL-derived edges for
// one object. It never panics on malformed input; it returns what it could read.
//
// targetKind lets the mask->edge mapping stay faithful: WriteProperty on a group
// is AddMember, on a user it is a generic write, and so on.
func parseSecurityDescriptor(sd []byte, targetKind parse.Kind) (owner string, edges []aclEdge) {
	if len(sd) < 20 {
		return "", nil
	}
	if sd[0] != 1 { // SECURITY_DESCRIPTOR_REVISION
		return "", nil
	}
	offOwner := int(binary.LittleEndian.Uint32(sd[4:8]))
	offDACL := int(binary.LittleEndian.Uint32(sd[16:20]))

	if offOwner > 0 && offOwner < len(sd) {
		owner = SIDString(sd[offOwner:])
	}
	if offDACL <= 0 || offDACL+8 > len(sd) {
		return owner, nil
	}

	acl := sd[offDACL:]
	aclSize := int(binary.LittleEndian.Uint16(acl[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(acl[4:6]))
	if aclSize > len(acl) {
		aclSize = len(acl)
	}

	pos := 8
	for i := 0; i < aceCount; i++ {
		if pos+8 > aclSize {
			break
		}
		aceType := acl[pos]
		aceFlags := acl[pos+1]
		aceSize := int(binary.LittleEndian.Uint16(acl[pos+2 : pos+4]))
		if aceSize < 8 || pos+aceSize > aclSize {
			break
		}
		ace := acl[pos : pos+aceSize]
		pos += aceSize

		// INHERIT_ONLY ACEs do not apply to this object.
		if aceFlags&aceInheritOnly != 0 {
			continue
		}
		if aceType != aceAccessAllowed && aceType != aceAccessAllowedObject {
			continue // deny ACEs and audit ACEs do not create attack edges
		}

		mask := binary.LittleEndian.Uint32(ace[4:8])
		var objectType string
		off := 8
		if aceType == aceAccessAllowedObject {
			if off+4 > len(ace) {
				continue
			}
			flags := binary.LittleEndian.Uint32(ace[off : off+4])
			off += 4
			if flags&aceObjectTypePresent != 0 {
				if off+16 > len(ace) {
					continue
				}
				objectType = GUIDString(ace[off : off+16])
				off += 16
			}
			if flags&aceInheritedObjectTypePresent != 0 {
				if off+16 > len(ace) {
					continue
				}
				off += 16 // inherited object type does not change the primitive
			}
		}
		if off >= len(ace) {
			continue
		}
		sid := SIDString(ace[off:])
		if sid == "" || isNoiseSource(sid) {
			continue
		}
		for _, t := range maskToEdges(mask, objectType, targetKind) {
			edges = append(edges, aclEdge{From: sid, Type: t})
		}
	}
	return owner, edges
}

// maskToEdges maps one ACE's access mask (and object GUID, if any) onto the
// normalized attack edges it grants.
func maskToEdges(mask uint32, objectType string, kind parse.Kind) []parse.EdgeType {
	var out []parse.EdgeType

	// Full control subsumes everything else; emit one edge, not eight.
	if mask&rightGenericAll != 0 || mask&rightFullControl == rightFullControl {
		// A GenericAll scoped to a single attribute is not full control.
		if objectType == "" || objectType == guidAllGuid {
			return []parse.EdgeType{parse.GenericAll}
		}
		switch strings.ToUpper(objectType) {
		case guidGMSAPassword:
			return []parse.EdgeType{parse.ReadGMSAPassword}
		case guidKeyCredentialLink:
			return []parse.EdgeType{parse.AddKeyCredentialLink}
		}
	}

	if mask&rightWriteDACL != 0 {
		out = append(out, parse.WriteDacl)
	}
	if mask&rightWriteOwner != 0 {
		out = append(out, parse.WriteOwner)
	}
	if mask&rightGenericWrite != 0 {
		out = append(out, parse.GenericWrite)
	}

	if mask&rightDSWriteProp != 0 {
		switch strings.ToUpper(objectType) {
		case "", guidAllGuid:
			// Write to every property.
			if kind == parse.KindGroup {
				out = append(out, parse.AddMember)
			}
			out = append(out, parse.GenericWrite)
		case guidAttrMember:
			out = append(out, parse.AddMember)
		case guidAttrSPN:
			out = append(out, parse.WriteSPN)
		case guidKeyCredentialLink:
			out = append(out, parse.AddKeyCredentialLink)
		case guidAllowedToAct:
			out = append(out, parse.AllowedToAct)
		}
	}

	if mask&rightDSSelf != 0 && strings.EqualFold(objectType, guidAttrMember) {
		out = append(out, parse.AddSelf)
	}

	if mask&rightDSControlAccess != 0 {
		switch strings.ToUpper(objectType) {
		case "", guidAllGuid:
			out = append(out, parse.AllExtendedRights)
		case guidForceChangePwd:
			out = append(out, parse.ForceChangePassword)
		case guidGetChanges:
			out = append(out, parse.GetChanges)
		case guidGetChangesAll:
			out = append(out, parse.GetChangesAll)
		case guidGetChangesFiltered:
			out = append(out, parse.GetChanges)
		case guidGMSAPassword:
			out = append(out, parse.ReadGMSAPassword)
		}
	}

	// CreateChild+DeleteChild on a container is not an escalation on its own;
	// deliberately not emitted, to keep the report's signal-to-noise honest.
	_ = rightDSCreateChild
	_ = rightDSDeleteChild
	_ = guidLAPSPassword

	return dedupeEdges(out)
}

func dedupeEdges(in []parse.EdgeType) []parse.EdgeType {
	if len(in) < 2 {
		return in
	}
	seen := make(map[parse.EdgeType]bool, len(in))
	out := in[:0]
	for _, e := range in {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}
