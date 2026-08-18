# AD Explorer snapshot support

Harbinger reads Sysinternals AD Explorer `.dat` snapshots **natively**. No
converter, no Python, no intermediate JSON.

## Why

SharpHound is flagged by essentially every EDR, because attackers use it. For a
pentest firm that is an accepted cost of doing business. For an MSP it is a
blocker: running it on their own network sets off their own alerts, and running
it on a client's network without warning is a trust incident.

AD Explorer is a Microsoft-signed Sysinternals tool that is already in every
Windows admin's toolkit and does not look like a hacking tool, because it is not
one. Taking a snapshot is a read of the directory that looks like a read of the
directory.

Supporting the format removes the single largest source of friction for this
audience. Doing it natively rather than by shelling out to
`ADExplorerSnapshot.py` removes the rest of it: the user does not install Python,
does not install a converter, and does not run a two-step pipeline.

## What is extracted

| From the snapshot | Becomes |
|---|---|
| `objectSid` / `objectGUID` | Node identity (SID for principals, GUID for OUs/GPOs/containers — matching BloodHound, so graphs are comparable) |
| `objectClass` | Node kind (User, Computer, Group, Domain, OU, GPO, CertTemplate, EnterpriseCA, …) |
| `member` | `MemberOf` |
| `primaryGroupID` | `MemberOf` (this is how a DC's Domain Controllers membership appears) |
| DN parent | `Contains` |
| `gPLink` | `GPLink` (disabled links skipped) |
| **`nTSecurityDescriptor`** | **`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`, `AllExtendedRights`, `ForceChangePassword`, `AddMember`, `AddSelf`, `AddKeyCredentialLink`, `WriteSPN`, `GetChanges`, `GetChangesAll` → `DCSync`** |
| `msDS-GroupMSAMembership` | `ReadGMSAPassword` |
| `msDS-AllowedToDelegateTo` | `AllowedToDelegate` (SPN host resolved via `dNSHostName`) |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | `AllowedToAct` (RBCD) |
| `sIDHistory` | `HasSIDHistory` |
| `userAccountControl` | enabled, is-DC, unconstrained delegation |

The security descriptor is the important row. Group membership alone finds
almost nothing; the DACL is where real escalation lives.

## What is not in a snapshot

An AD Explorer snapshot is an LDAP dump. It cannot contain anything that
requires talking to individual machines:

- **Sessions** — no `HasSession` edges.
- **Local group membership** — no `AdminTo`, `CanRDP`, `CanPSRemote`,
  `ExecuteDCOM`.

Every snapshot-derived report declares both gaps explicitly. A route that was
not collected is invisible, not absent.

## Noise reduction

ACEs granted to principals that are already Tier Zero are dropped as edge
*sources*: Domain Admins, Enterprise Admins, Schema Admins, Domain Controllers,
BUILTIN\Administrators, plus `CREATOR OWNER`, `SELF`, `LOCAL SYSTEM`, and
`ENTERPRISE DOMAIN CONTROLLERS`. Without this a real directory produces millions
of trivially-true edges that bury the finding.

Paths *to* those groups are of course kept — they are the objective. Only the
source side is filtered. See `noiseSIDs` / `noiseRIDs` in
`internal/adexplorer/secdesc.go`; the list is short and deliberately explicit.

## Robustness

A snapshot is untrusted input, and real ones are truncated, half-copied, or from
a version of AD Explorer nobody has seen. The parser therefore:

- bounds-checks every read against the file length;
- caps every length-prefixed allocation;
- treats an unreadable attribute, object, or ACE as skippable, with a warning,
  rather than fatal;
- stops the object index cleanly at the first implausible record and reports how
  many objects it got;
- recovers from any panic at the `Ingest` boundary and converts it into an
  actionable message.

Covered by `TestMalformedInputsFailCleanly` and `TestCorruptionNeverPanics`,
which sweeps a bit-flip across the whole file and asserts no panic at any offset.

## Format reference

The on-disk layout is documented by
[c3c/ADExplorerSnapshot.py](https://github.com/c3c/ADExplorerSnapshot.py) (MIT).
No code from that project is used here — only the structure definitions were
consulted. Thanks to c3c for reverse engineering and publishing the format.

Layout in brief:

```
0x000  header      sig "win-ad-obj", filetime, description[260], server[260],
                   numObjects, numAttributes, metadataOffset, treeviewOffset
0x43E  objects     [objSize u32][tableSize u32][(attrIndex u32, attrOffset i32) × tableSize][values…]
meta   properties  [numProperties u32][ lenName, name, unk, adsType, lenDN, DN, guids ]
       classes, rights
```

Attribute values are encoded by ADS type: string types store offsets to
NUL-terminated UTF-16 (which may be negative, pointing into an earlier object);
octet strings store all lengths then the bytes; security descriptors store
`(length, bytes)` pairs.

## Trying it without a real directory

```sh
harbinger gen-testdata --format=adexplorer sample.dat
harbinger analyze sample.dat
```

This writes a real, valid snapshot containing a known escalation path, so you
can confirm the `.dat` path works on your machine before pointing the tool at a
client's directory. `harbinger check` runs the same thing as a self-test.
