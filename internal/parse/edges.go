package parse

import "strings"

// EdgeType is a normalized BloodHound attack edge.
type EdgeType string

const (
	// Membership / structure
	MemberOf EdgeType = "MemberOf"
	Contains EdgeType = "Contains"
	GPLink   EdgeType = "GPLink"

	// ACLs
	GenericAll           EdgeType = "GenericAll"
	GenericWrite         EdgeType = "GenericWrite"
	WriteDacl            EdgeType = "WriteDacl"
	WriteOwner           EdgeType = "WriteOwner"
	Owns                 EdgeType = "Owns"
	AllExtendedRights    EdgeType = "AllExtendedRights"
	ForceChangePassword  EdgeType = "ForceChangePassword"
	AddMember            EdgeType = "AddMember"
	AddSelf              EdgeType = "AddSelf"
	AddKeyCredentialLink EdgeType = "AddKeyCredentialLink"
	WriteSPN             EdgeType = "WriteSPN"

	// Session / execution
	AdminTo     EdgeType = "AdminTo"
	HasSession  EdgeType = "HasSession"
	CanRDP      EdgeType = "CanRDP"
	CanPSRemote EdgeType = "CanPSRemote"
	ExecuteDCOM EdgeType = "ExecuteDCOM"
	SQLAdmin    EdgeType = "SQLAdmin"

	// Delegation
	AllowedToDelegate EdgeType = "AllowedToDelegate"
	AllowedToAct      EdgeType = "AllowedToAct" // RBCD

	// Replication / secrets
	GetChanges       EdgeType = "GetChanges"
	GetChangesAll    EdgeType = "GetChangesAll"
	DCSync           EdgeType = "DCSync"
	ReadLAPSPassword EdgeType = "ReadLAPSPassword"
	ReadGMSAPassword EdgeType = "ReadGMSAPassword"

	// ADCS (ESC1-ESC16 family collapse to a single normalized edge with a subtype label)
	ADCSESC EdgeType = "ADCSESC"

	// Coercion / other
	HasSIDHistory    EdgeType = "HasSIDHistory"
	SyncLAPSPassword EdgeType = "SyncLAPSPassword"

	EdgeUnknown EdgeType = "Unknown"
)

// aclRights is the set of edge types that are derived from an object ACE.
var aclRights = map[EdgeType]bool{
	GenericAll: true, GenericWrite: true, WriteDacl: true, WriteOwner: true,
	Owns: true, AllExtendedRights: true, ForceChangePassword: true, AddMember: true,
	AddSelf: true, AddKeyCredentialLink: true, WriteSPN: true, GetChanges: true,
	GetChangesAll: true, ReadLAPSPassword: true, ReadGMSAPassword: true, SyncLAPSPassword: true,
}

// normalizeEdgeType maps a raw BloodHound RightName/edge label onto our enum,
// tolerating casing and unknown/new edges (returned as EdgeUnknown, logged upstream).
func normalizeEdgeType(raw string) EdgeType {
	r := strings.TrimSpace(raw)
	switch strings.ToLower(r) {
	case "memberof":
		return MemberOf
	case "contains":
		return Contains
	case "gplink":
		return GPLink
	case "genericall":
		return GenericAll
	case "genericwrite":
		return GenericWrite
	case "writedacl":
		return WriteDacl
	case "writeowner":
		return WriteOwner
	case "owns":
		return Owns
	case "allextendedrights":
		return AllExtendedRights
	case "forcechangepassword":
		return ForceChangePassword
	case "addmember":
		return AddMember
	case "addself":
		return AddSelf
	case "addkeycredentiallink":
		return AddKeyCredentialLink
	case "writespn":
		return WriteSPN
	case "adminto":
		return AdminTo
	case "hassession":
		return HasSession
	case "canrdp":
		return CanRDP
	case "canpsremote":
		return CanPSRemote
	case "executedcom":
		return ExecuteDCOM
	case "sqladmin":
		return SQLAdmin
	case "allowedtodelegate":
		return AllowedToDelegate
	case "allowedtoact":
		return AllowedToAct
	case "getchanges":
		return GetChanges
	case "getchangesall":
		return GetChangesAll
	case "dcsync":
		return DCSync
	case "readlapspassword":
		return ReadLAPSPassword
	case "readgmsapassword":
		return ReadGMSAPassword
	case "hassidhistory":
		return HasSIDHistory
	case "synclapspassword":
		return SyncLAPSPassword
	}
	// ADCS ESC1..ESC16 and friends
	if strings.HasPrefix(strings.ToUpper(r), "ADCSESC") || strings.HasPrefix(strings.ToUpper(r), "ESC") {
		return ADCSESC
	}
	if strings.EqualFold(r, "enroll") || strings.EqualFold(r, "enrollonbehalfof") ||
		strings.EqualFold(r, "manageca") || strings.EqualFold(r, "managecertificates") {
		return ADCSESC
	}
	return EdgeUnknown
}

// EdgeProfile is the per-edge-type attack-primitive prior: how likely the step
// succeeds under a typical config, and how likely native/EDR telemetry catches it.
// These priors drive both pathfinding cost and the OFFLINE distilled scorer.
// They are deliberately conservative and documented; the server's full model
// supersedes them in hybrid mode.
type EdgeProfile struct {
	Success   float64 // P(step works)
	Detection float64 // P(defender sees it with common telemetry)
	Label     string  // human-friendly primitive name for the report
}

var edgeProfiles = map[EdgeType]EdgeProfile{
	MemberOf:             {0.99, 0.02, "group membership"},
	Contains:             {0.99, 0.02, "OU/container containment"},
	GPLink:               {0.85, 0.25, "GPO link abuse"},
	GenericAll:           {0.95, 0.35, "full control (GenericAll)"},
	GenericWrite:         {0.90, 0.30, "write property (GenericWrite)"},
	WriteDacl:            {0.90, 0.40, "modify DACL"},
	WriteOwner:           {0.88, 0.35, "take ownership"},
	Owns:                 {0.92, 0.30, "owner rights"},
	AllExtendedRights:    {0.90, 0.35, "all extended rights"},
	ForceChangePassword:  {0.85, 0.55, "force password reset"},
	AddMember:            {0.95, 0.45, "add to group"},
	AddSelf:              {0.95, 0.40, "add self to group"},
	AddKeyCredentialLink: {0.88, 0.25, "shadow credentials (msDS-KeyCredentialLink)"},
	WriteSPN:             {0.80, 0.50, "targeted kerberoast (WriteSPN)"},
	AdminTo:              {0.97, 0.40, "local admin -> credential theft"},
	HasSession:           {0.70, 0.30, "harvest live session credential"},
	CanRDP:               {0.85, 0.45, "RDP logon"},
	CanPSRemote:          {0.85, 0.50, "PSRemoting"},
	ExecuteDCOM:          {0.75, 0.45, "DCOM execution"},
	SQLAdmin:             {0.80, 0.40, "SQL admin -> host"},
	AllowedToDelegate:    {0.80, 0.40, "constrained delegation abuse"},
	AllowedToAct:         {0.82, 0.35, "resource-based constrained delegation"},
	GetChanges:           {0.95, 0.20, "replication (GetChanges)"},
	GetChangesAll:        {0.95, 0.20, "replication (GetChangesAll)"},
	DCSync:               {0.97, 0.35, "DCSync (dump all secrets)"},
	ReadLAPSPassword:     {0.95, 0.20, "read LAPS password"},
	ReadGMSAPassword:     {0.95, 0.15, "read gMSA password"},
	ADCSESC:              {0.85, 0.30, "AD CS escalation (ESC family)"},
	HasSIDHistory:        {0.90, 0.15, "SID history injection"},
	SyncLAPSPassword:     {0.90, 0.20, "sync LAPS password"},
	EdgeUnknown:          {0.60, 0.50, "unmodeled edge"},
}

// Profile returns the attack prior for an edge type (falling back to Unknown).
func (t EdgeType) Profile() EdgeProfile {
	if p, ok := edgeProfiles[t]; ok {
		return p
	}
	return edgeProfiles[EdgeUnknown]
}

// IsACL reports whether the edge is ACL-derived.
func (t EdgeType) IsACL() bool { return aclRights[t] }
