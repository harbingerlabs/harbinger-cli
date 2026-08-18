# Harbinger — Data Handling Statement

One page. Written to be checked rather than believed: the client is source
available, so every claim below can be verified against the code or observed
with a network monitor.

**Product:** Harbinger CLI (`harbinger`), a single signed executable.
**Applies to:** all commands. **Last updated:** 2026-08-14.

---

## The short answer

**Nothing leaves your machine.** Harbinger reads one local file and writes a
report next to it. In its default mode it opens no network connections at all —
not to us, not to anyone. You can disconnect the machine from the network
entirely and every command behaves identically.

---

## What it reads

One file that you point it at:

- an **AD Explorer snapshot** (`.dat`), or
- a **BloodHound/SharpHound export** (`.zip`, a folder of `.json`, or one `.json`).

That is the complete input. It reads nothing else on the machine.

## What it never does

- **Never contacts Active Directory.** No LDAP, no SMB, no RPC, no domain
  controller. It cannot: there is no directory client in the binary.
- **Never uses credentials.** It does not prompt for them, read them, or store
  them. It has no credential store.
- **Never writes to your directory.** The analysis is entirely read-only, and
  it reads a file, not the directory.
- **Never installs anything.** Single executable. No service, no driver, no
  scheduled task, no registry keys beyond what Windows records for any process.
- **Never requires administrator rights.**
- **No telemetry, no licence check, no update beacon, no analytics.**

## What leaves the machine

**Nothing**, in default (offline) operation.

The only exception is opt-in and explicit: if you pass `--api-key`, the tool
uses the hosted scoring model instead of the local one. Even then it transmits
only **anonymized, tokenized structural features** — never names, SIDs, GUIDs,
SPNs, distinguished names, or descriptions. Specifically, per candidate path:

- a **per-run random token** for the path and each node (e.g. `n_2fce_00042`),
  regenerated every run from a cryptographic seed, so the server cannot
  correlate two runs or reverse a token to an identity;
- the **edge-type sequence** (`MemberOf`, `GenericAll`, …) — attack-primitive
  categories, not identifiers;
- **coarse structural features**: hop count, counts of ACL/execution/delegation/
  replication edges, whether the path crosses a domain boundary, and node
  degrees **bucketed** into ranges so a degree cannot fingerprint an object;
- the **object kind** of each end (`User`, `Group`, `Domain`).

The server can score "a path shaped like this" but cannot learn "Alice can reach
Domain Admin." Tokens are mapped back to real names **locally**, on your
machine, to render the report.

**See exactly what would be sent, without sending it:**

```
harbinger analyze <export> --show-payload
```

## What it writes

Only what you ask for: the terminal output, and the file named by `--report`
or `--json`. No temporary copies of your export, no cache, no log file.

---

## How to verify all of this yourself

1. **Read the boundary.** `internal/features/features.go` is the only place
   where information is selected for possible transmission. If it is not put
   into a `ScoreRequest` there, it cannot leave.
2. **Read the payload.** `harbinger analyze <export> --show-payload`.
3. **Watch the wire.** Run `harbinger analyze <export> --offline` behind
   Wireshark, Little Snitch, or your egress firewall. Expect zero connections.
4. **Run the tests.** `go test ./...` includes `TestNoIdentityLeak`, which fails
   the build if any name, SID, or domain string from the graph appears in the
   serialized payload. `harbinger check` runs the same assertion end to end on
   your own machine, in about a second.
5. **Verify the binary.** Compare against the published `SHA256SUMS`, or rebuild
   it yourself: the build is reproducible with `go build -trimpath`.

---

## Handling the export itself

The export is yours and stays yours, but it is sensitive: it contains staff
names, group memberships, and your permission structure. Treat it as you would
any directory documentation — store it where client AD documentation lives, and
delete it when the engagement ends. Harbinger neither moves nor copies it.

If you need to share a report outside the team that owns the data, the HTML
report is self-contained (no external requests, no fonts, no scripts) and can be
reviewed before it is sent.

---

## Honest limits — we will not overclaim

- **Tokenized structure is not zero information.** In hybrid mode the server
  learns the *shape* of your paths (how many hops, which edge types, how they
  branch), just not who anyone is. If your threat model cannot tolerate that,
  use the default offline mode, which transmits nothing at all.
- **The offline model is a distilled approximation** of the hosted, calibrated
  one. It is lower quality by design; that is the price of zero transmission.
- **Scores are structural priors, not guarantees.** "Unlikely to be detected"
  assumes common native and endpoint telemetry, not your specific tuned EDR.
- **A collection gap is not safety.** An AD Explorer snapshot cannot see logged-on
  sessions or local group membership. Every report states what the run could not
  see, and no report treats "no path found" as a clean bill of health.

---

**Questions this document does not answer** — ask, and we will answer in writing
and add it here: security@harbingerlabs.ai · <https://harbingerlabs.ai>
