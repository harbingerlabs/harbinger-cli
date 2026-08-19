<p align="center">
  <img src="assets/logo.png?v=2" alt="Harbinger" width="88" height="88">
</p>

<h1 align="center">Harbinger</h1>

<p align="center">
  <b>Find the routes to Domain Admin that your monitoring would not catch —<br>
  without your Active Directory data ever leaving the machine.</b>
</p>

<p align="center">
  <a href="https://github.com/harbingerlabs/harbinger-cli/actions/workflows/ci.yml"><img src="https://github.com/harbingerlabs/harbinger-cli/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/network%20calls-0-brightgreen" alt="Zero network calls">
  <img src="https://img.shields.io/badge/go-1.26-00ADD8" alt="Go 1.26">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
</p>

<p align="center">
  <a href="docs/QUICKSTART.md">Quickstart</a> ·
  <a href="docs/COLLECTING.md">Collecting</a> ·
  <a href="docs/DATA_HANDLING.md">Data handling</a> ·
  <a href="docs/VERIFY.md">Verify the binary</a>
</p>

---

Active Directory accumulates permissions for twenty years and nobody removes any
of them. Somewhere in that sprawl is a chain from an ordinary account to complete
control of the domain. Harbinger finds those chains, ranks them by whether your
monitoring would actually notice someone using them, and names the one change
that closes the most of them.

It reads a file. It never touches your directory, never uses credentials, and in
its default mode opens no network connections at all.

```
$ harbinger gen-testdata --format=adexplorer sample.dat
$ harbinger analyze sample.dat

  HARBINGER — attack-path exposure analysis
  ──────────────────────────────────────────────────────
  Loaded 8 objects across 12 edge(s)
  Crown objective: DOMAIN ADMINS@CORP.LOCAL

  ⚠  5 routes to full control of DOMAIN ADMINS would
     probably not be noticed while it was being used.

  Do this first
     Remove SVC-BACKUP@CORP.LOCAL's directory replication
     rights (Replicating Directory Changes and Replicating
     Directory Changes All) on CORP.LOCAL. On its own this
     closes 2 of the ranked routes.

  What this run could NOT see
     - Sessions were not collected — paths that start from
       a logged-on user's credential are invisible here.

  Top 5 paths (ranked by reachable-and-undetected risk)

  #1  risk 0.749 | 1 hop  | 77% evasion — BLIND SPOT
     SVC-BACKUP@CORP.LOCAL ─[DCSync]─ CORP.LOCAL

  #2  risk 0.480 | 2 hops | 61% evasion — BLIND SPOT ★crown
     HELPDESK@CORP.LOCAL ─[GenericAll]─ TIER1ADMINS@CORP.LOCAL
       ⇢[MemberOf]⇢ DOMAIN ADMINS@CORP.LOCAL
```

Those two commands work on your machine right now, against a synthetic directory
the tool writes itself — no client data, no network. The output above is that run,
trimmed for length.

## Install

**From source** — the build is reproducible; the same tag produces byte-identical
output on any machine.

```sh
go install github.com/harbingerlabs/harbinger-cli/cmd/harbinger@latest
```

Or clone and build:

```sh
git clone https://github.com/harbingerlabs/harbinger-cli
cd harbinger-cli
make build          # -> bin/harbinger
```

> **Signed binaries are not published yet.** Releases will carry Authenticode-signed
> Windows executables with published `SHA256SUMS`; the code-signing certificate is
> in progress. Until then, build from source — an unsigned security tool is worse
> than no download at all, so we are not shipping one.
> See [docs/SIGNING.md](docs/SIGNING.md).

Then confirm it works, before it ever sees client data:

```sh
harbinger check
```

Runs the whole pipeline against a synthetic directory and asserts the privacy
invariant end to end. About a second. No file, no network.

## You do not need BloodHound

Most Windows admins have never run SharpHound, and running it will very likely
trip their EDR — attackers use the same tool, so every endpoint product detects
it. On a client network that is not a false positive; it is an incident.

**Harbinger reads Sysinternals AD Explorer snapshots natively.** AD Explorer is
signed by Microsoft, already trusted in a Windows shop, and taking a snapshot
looks like what it is: an administrator reading LDAP.

```
File > Create Snapshot   →   harbinger analyze snapshot.dat
```

Already have a BloodHound export? That works too — a `.zip`, a folder of
`.json`, or a single `.json`, in either the **CE** or the older **Legacy**
schema. The format is detected from the file's contents, so a renamed file
still works.

→ **[docs/COLLECTING.md](docs/COLLECTING.md)** — the full walkthrough, including
what a snapshot can and cannot see. `harbinger help collecting` prints the same
thing offline, from inside the binary.

## Your data never leaves your machine

**There is no upload path in the default mode.** Not disabled by default — the
tool opens no network connections at all. Disconnect the machine and every
command behaves identically.

- Reads one local file, read-only.
- Never contacts Active Directory. Never uses credentials. It has no directory
  client and no credential store.
- No telemetry. No licence check. No update beacon.
- Zero third-party dependencies — stdlib Go only, so the code you have to read
  to verify that claim is small and self-contained.

Verify it rather than believe it:

```sh
harbinger check                           # self-test + privacy assertion
harbinger analyze <export> --show-payload # what hybrid mode WOULD send
harbinger analyze <export> --offline      # run it behind a packet capture
```

→ **[docs/DATA_HANDLING.md](docs/DATA_HANDLING.md)** — the one-page statement.
A reviewer should start at `internal/features/features.go`: if a value is not
put into a `ScoreRequest` there, it cannot leave the machine.

## What you get

**A collection gap is never reported as safety.** Every report states what it
could not see. "No path found" because sessions were not collected says exactly
that, rather than implying you are clean.

**One document, two readers.** The plain-English layer comes first, so the person
who decides whether the work gets scheduled can read it without knowing what
`GenericAll` means. The ranked paths below stay precise enough for the engineer
making the change.

**Routes, not rows.** Every member of a group holding a permission can walk the
same route with the same fix. That is one finding and a count, not fifteen
findings.

**Ranked by whether you would notice.** A route that is reachable *and* quiet
outranks a shorter one that would light up your SIEM.

```sh
harbinger analyze export.dat --report client.html
```

writes a self-contained HTML report you can send to a client — no external
requests, no fonts, no scripts — with a real print stylesheet, because these get
turned into PDFs.

## What changed since last time

```sh
harbinger diff before.dat after.dat
```

Reports both directions: routes that **opened**, and routes that **closed** —
the evidence a fix actually landed. Changes are grouped by cause, with
configuration changes ranked above session churn, so a newly granted DCSync is
never buried under "an admin logged into a different workstation".

Comparing two different directories is detected and called out rather than
silently producing nonsense.

## Several clients on one machine

Normal for an MSP, and handled. If an export spans more than one directory,
Harbinger lists every one it found and tells you which it ranked against:

```sh
harbinger analyze forest.dat --domain acme.local
```

A folder holding two clients' snapshots is refused rather than resolved by
guessing — picking one silently is how a report reaches the wrong customer.

## Commands

```sh
harbinger analyze <export> [flags]   ranked routes + the top fix
harbinger diff <t0> <t1>             what opened, what closed
harbinger check                      self-test; no file, no network
harbinger gen-testdata [dir|file]    write a sample export to try
harbinger help [topic]               the manual, offline, in the binary
harbinger version                    client + feature schema version
```

The three documents you need before a first run — how to collect, what leaves
the machine, how to verify the binary — are **carried inside the executable**:
`harbinger help collecting`, `help privacy`, `help verify`. No checkout and no
browser needed on the machine you are running from.

### Flags worth knowing

| Flag | What it does |
|---|---|
| `--report out.html` | self-contained report (`.html` or `.md`) you can send to a client |
| `--json` | structured output for a PSA/RMM — see below |
| `--domain <name>` | restrict to one directory when the export holds several |
| `--top N` | routes to show (default 10) |
| `--hvt a,b` | designate extra High-Value Targets by SID or name |
| `--max-starts N` | bound the search on a very large directory |
| `--show-payload` | print exactly what hybrid mode would transmit |
| `--offline` | force fully-local scoring (this is the default) |
| `--no-color` | disable ANSI; `NO_COLOR=1` also honoured |

### Exit codes

`0` success · `1` runtime error (unreadable export, scoring failure) · `2` usage error.

### JSON output

`--json` emits a versioned envelope so a script can assert on the shape before
trusting it:

```json
{
  "schema": "harbinger.analysis/1",
  "client": "distilled-1.0.0",
  "result": {
    "crown_name": "DOMAIN ADMINS@CORP.LOCAL",
    "paths": [
      {
        "rank": 1, "risk": 0.749, "hops": 1, "evasion": 0.77,
        "blind_spot": true, "start_count": 3,
        "steps": [
          {"from_name": "SVC-BACKUP@CORP.LOCAL",
           "to_name": "CORP.LOCAL", "edge": "DCSync"}
        ]
      }
    ],
    "top_fix": {
      "from_name": "…", "to_name": "…",
      "edge": "DCSync", "paths_killed": 2
    }
  }
}
```

Check `schema` and fail loudly if it is not the version you built against.
`harbinger diff --json` uses `harbinger.diff/1`. Within a major version, fields
may be added, never removed or renamed.

## Building it yourself

```sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags "-s -w" -o harbinger ./cmd/harbinger
go test ./...
```

`-buildvcs=false` is not optional if you intend to compare hashes: without it Go
stamps the commit — and whether your working tree was clean — into the binary,
and no two builds agree. CI builds twice, once from a deliberately dirty tree,
and fails if the hashes differ. → **[docs/VERIFY.md](docs/VERIFY.md)**

The tests a reviewer should care about, by name:

| Test | What it prevents |
|---|---|
| `TestNoIdentityLeak` | any identifier reaching the outbound payload |
| `TestLegacyAndCEProduceIdenticalGraphs` | old and new BloodHound schemas disagreeing |
| `TestCorruptionNeverPanics` | a bit-flip anywhere in a snapshot crashing the parser |
| `TestFolderWithTwoSnapshotsIsRefused` | one client's report being built from another's export |
| `TestExistingAdminIsNotAStartingPoint` | "an admin is an admin" ranking above real findings |
| `TestEveryHelpTopicHasEmbeddedContent` | the offline manual silently not shipping |

## Limitations

Worth reading before you rely on it.

- **Scores are structural priors, not guarantees.** "Unlikely to be detected"
  assumes common native and endpoint telemetry, not your specific tuned EDR.
- **The offline model is a distilled approximation** of the calibrated hosted
  one. Every report says which scorer produced it.
- **An LDAP-only snapshot cannot see sessions or local group membership**, so
  host-to-host lateral movement is invisible in that mode. The report says so
  on its face rather than reporting a clean result.
- **No MSP has run this in production yet.** It is early. If it is wrong about
  your directory, we want to hear about it.

## Documentation

| | |
|---|---|
| [QUICKSTART.md](docs/QUICKSTART.md) | A result in under ten minutes |
| [COLLECTING.md](docs/COLLECTING.md) | How to get the data, including the EDR warning |
| [DATA_HANDLING.md](docs/DATA_HANDLING.md) | What it reads, what it never does, what leaves (nothing) |
| [VERIFY.md](docs/VERIFY.md) | Signature, checksums, reproducible build |
| [ADEXPLORER.md](docs/ADEXPLORER.md) | Snapshot support: what is extracted, what is not |
| [SIGNING.md](docs/SIGNING.md) | Code-signing setup and release process |
| [PILOT.md](docs/PILOT.md) | Design-partner pilot: shape, duration, what we ask |
| [MUTUAL_NDA.md](docs/MUTUAL_NDA.md) | Mutual NDA template, ready to send |
| [FEEDBACK.md](docs/FEEDBACK.md) | Pre-registered measurement instrument |

## Reporting a problem

A wrong answer about a customer's directory is the failure that matters most, so
those reports are welcome and get priority. Open an issue — or for anything that
looks like a vulnerability in the client or the signed binaries, email
**security@harbingerlabs.ai** rather than filing publicly.

If a verification step in our own documentation does not check out, that is a
bug in the software or the document, and we want to know either way.


## License

MIT — see [LICENSE](LICENSE).

Built by [Harbinger Labs](https://harbingerlabs.ai).
