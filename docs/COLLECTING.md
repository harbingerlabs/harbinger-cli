# Collecting the data

**Read this before you collect anything.** It takes about five minutes and it
covers the one thing that surprises people: the standard tool for this job will
set off your EDR.

You do not need BloodHound, and you do not need to have used it before.

---

## The short version

**Use AD Explorer.** It is a Microsoft Sysinternals tool, signed by Microsoft,
that you may already have. Take a snapshot, point Harbinger at the `.dat` file,
done. No conversion step, no Python, no security tooling on the wire.

```
harbinger analyze snapshot.dat
```

---

## Option 1 — AD Explorer (recommended)

### Why this one

| | AD Explorer | SharpHound |
|---|---|---|
| Publisher | Microsoft (Sysinternals) | An offensive-security project |
| Signed | Yes, by Microsoft | Yes, but by a security-tools publisher |
| Your EDR | Ignores it | **Very likely alerts or blocks** |
| Looks like | An admin browsing LDAP | A tool attackers use in the same way |
| Needs install | No | No |
| Needs admin | No — any domain user | No — any domain user |

AD Explorer is an LDAP browser. Taking a snapshot is a read of the directory
that looks like a read of the directory, because that is what it is.

### Steps

1. Download **AD Explorer** from Microsoft:
   <https://learn.microsoft.com/sysinternals/downloads/adexplorer>
   Verify it is signed by Microsoft before running it — right-click →
   Properties → Digital Signatures.

2. Run `ADExplorer.exe` (or `ADExplorer64.exe`). Accept the EULA.

3. Connect:
   - **Connect to:** leave blank to use the domain controller you are already
     talking to, or type a DC hostname.
   - **User / Password:** leave blank to use your current credentials. Any
     ordinary domain user account is enough. **Do not** use a Domain Admin
     account for this — it is not needed, and using one adds risk for no gain.

4. **File → Create Snapshot…**
   - Give it a path, e.g. `C:\temp\client-2026-08-14.dat`.
   - Leave the naming/comment fields as you like.
   - Click **OK** and wait.

5. Wait for it to finish. This is the step people get wrong.
   - Small directory (< 5,000 objects): a minute or two.
   - Medium (5,000–50,000): 5–20 minutes.
   - Large (50,000+): can exceed an hour.
   - **The file is not usable until the snapshot completes.** If you copy it
     while AD Explorer is still writing, Harbinger will tell you the file is
     truncated. Wait for the progress dialog to close.

6. Run Harbinger against the file:
   ```
   harbinger analyze C:\temp\client-2026-08-14.dat --report client-report.html
   ```

### What a snapshot contains, and what it does not

**Contains** — everything Harbinger needs for directory-permission attack paths:
users, computers, groups, OUs, GPOs, group membership, delegation, SID history,
and the security descriptors (ACLs) that hold most real escalation routes.

**Does not contain** — anything that requires talking to individual machines:

- **Logged-on sessions.** Routes that start by stealing a credential from a
  machine someone is logged into are invisible.
- **Local administrator / RDP / PSRemote group membership.** Host-to-host
  lateral movement is invisible.

Harbinger states both of these at the top of every snapshot-derived report. A
route that was not collected is invisible, **not absent** — the report never
reports a collection gap as safety.

For most first conversations this is the right trade: you get the directory
permission picture, which is where the durable problems live, without putting a
flagged tool on a client network.

### Where the snapshot file goes

Nowhere. Harbinger reads it locally and writes a report next to it. Nothing is
uploaded. See [DATA_HANDLING.md](DATA_HANDLING.md).

Treat the `.dat` like any directory export: it contains staff names and group
memberships. Store it where you would store a client's AD documentation, and
delete it when the engagement is done.

---

## Option 2 — SharpHound / BloodHound

Use this when you need the full picture including sessions and local admin
rights — for example on a second pass, or for a client who has already
authorized active security testing.

### ⚠ Expect your EDR to alert

**SharpHound will very likely trigger your endpoint protection.** This is not a
bug and it is not a false positive in any useful sense: attackers use SharpHound,
so Defender, CrowdStrike, SentinelOne, Sophos and the rest all detect it.
Depending on your product and configuration, the file may be quarantined on
download, blocked on execution, or allowed to run while generating an alert.

**Before you run it:**

1. Tell whoever watches your alert queue that you are doing it, when, and from
   which host. An unexplained SharpHound detection at 2am is a genuine incident
   until proven otherwise, and you do not want to be the cause of a callout.
2. If you are running it against a **client's** network, get that in writing
   first. A SharpHound detection on a client's estate that you did not warn them
   about is a serious trust problem, and it will land in their SOC, not yours.
3. Expect to need a temporary exclusion, scoped to one host and one time window.
   Remove it afterwards.

This is precisely why AD Explorer is the recommended path for a first look.

### Steps

1. Get SharpHound from the BloodHound project releases.
2. From a domain-joined machine, as any domain user:
   ```
   SharpHound.exe --collectionmethods Default,ACL,ObjectProps,Session
   ```
   (`Default` covers group membership, trusts, local admin, and sessions.)
3. It writes a timestamped `.zip`. Point Harbinger at it directly:
   ```
   harbinger analyze 20260814120000_BloodHound.zip
   ```

Both **BloodHound CE** and older **Legacy** schemas are supported — you do not
need to be on current tooling.

---

## Option 3 — an export you already have

If someone has already run BloodHound, Harbinger takes any of:

- the `.zip` SharpHound produced,
- the folder of `.json` files,
- a single `.json` file.

The format is detected from the file contents, so a renamed file still works.

---

## Repeat collections and the diff

The second run is where this gets useful. Take a snapshot before you make a
change and one after, then:

```
harbinger diff before.dat after.dat
```

It reports both directions: routes that **opened**, with the change responsible
for each, and routes that **closed** — the evidence that the fix landed. You can
mix formats; comparing a `.dat` against a BloodHound `.zip` is fine.

If the two snapshots turn out to be different directories, Harbinger says so
instead of producing confident nonsense.

---

## Several clients on one machine

Normal for an MSP, and handled. Keep each client's export as its own file:

```
harbinger analyze clients\acme\2026-08-14.dat  --report acme.html
harbinger analyze clients\globex\2026-08-14.dat --report globex.html
```

If a single export spans multiple directories (a forest, or a snapshot taken at
a level that caught several), Harbinger lists every directory it found and tells
you which one it ranked against. Pin one explicitly:

```
harbinger analyze forest.dat --domain acme.local
```

Naming an unknown domain lists the ones actually present rather than failing
vaguely.

---

## Troubleshooting

**"ends in .dat but does not carry the AD Explorer snapshot signature"**
The snapshot did not finish writing, or the file was copied mid-write. Re-take
it and wait for the dialog to close.

**"object index stops at N of M objects"**
A truncated snapshot. Harbinger analyzes what it can read and warns you. Re-take
it for a complete picture.

**"contains no directory objects with a resolvable identity"**
AD Explorer was connected to the RootDSE or the schema rather than to a domain
naming context. Reconnect and make sure the tree shows `DC=yourdomain,DC=local`
before taking the snapshot.

**No paths found**
Read the "What this run could not see" section of the report before treating
this as good news. With a snapshot, session-based and host-to-host routes are
never visible.

**It is slow on a large directory**
Bound the search: `--max-starts 5000` caps how many low-privilege starting
accounts are considered. The ranking stays meaningful; the run gets much faster.
