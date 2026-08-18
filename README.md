<p align="center">
  <img src="assets/logo.svg" alt="Harbinger Labs" width="76" height="76">
</p>

# Harbinger CLI

**Find the routes to Domain Admin your monitoring would not catch — without your
Active Directory data ever leaving the machine.**

One signed executable. No installer, no runtime, no admin rights, no account.

```
harbinger analyze snapshot.dat
```

That is the whole experience: point it at an AD Explorer snapshot or a BloodHound
export and get a ranked report with a single top fix.

---

## Start here

| If you are… | Read |
|---|---|
| about to run it and want to check it first | **[docs/VERIFY.md](docs/VERIFY.md)** |
| wondering what leaves your machine | **[docs/DATA_HANDLING.md](docs/DATA_HANDLING.md)** |
| not sure how to get the data | **[docs/COLLECTING.md](docs/COLLECTING.md)** |
| a security reviewer | [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md) then `internal/features/features.go` |

---

## You do not need BloodHound

Most Windows admins have never run SharpHound, and running it will very likely
trip their EDR — attackers use the same tool, so every endpoint product detects
it. On a client network that is not a false positive, it is an incident.

**Harbinger reads Sysinternals AD Explorer snapshots natively.** AD Explorer is
signed by Microsoft, already trusted in a Windows shop, and taking a snapshot
looks like what it is: an admin reading LDAP. No converter, no Python, no
two-step pipeline.

```
File > Create Snapshot  →  harbinger analyze snapshot.dat
```

Full walkthrough, including what a snapshot can and cannot see:
**[docs/COLLECTING.md](docs/COLLECTING.md)**.

Already have a BloodHound export? That works too — `.zip`, a folder of `.json`,
or a single `.json`, in either the **CE** or the older **Legacy** schema. The
format is detected from the file contents, so a renamed file still works.

---

## Your data never leaves your machine

**There is no upload path in the default mode.** Not disabled by default — the
tool opens no network connections at all. Disconnect the machine and every
command behaves identically.

- Reads one local file. Read-only.
- Never contacts Active Directory. Never uses credentials. It has no directory
  client and no credential store.
- No telemetry, no licence check, no update beacon.

Verify it rather than believe it:

```sh
harbinger check                              # self-test + privacy assertion, ~1s
harbinger analyze <export> --show-payload    # exactly what hybrid mode WOULD send
harbinger analyze <export> --offline         # run it behind a packet capture
```

→ **[docs/DATA_HANDLING.md](docs/DATA_HANDLING.md)** — the one-page statement.

---

## What you get

```
  ⚠  3 routes to full control of DOMAIN ADMINS would probably not be
     noticed while it was being used.

  Someone who compromised one ordinary account could reach complete
  control of this directory, and the steps involved are ones that
  routine monitoring is unlikely to alert on.

  Do this first
     Remove HELPDESK@CORP.LOCAL's full control (GenericAll) over
     TIER1ADMINS@CORP.LOCAL. On its own this closes 4 of the ranked routes.

  What this run could NOT see
     - Sessions were not collected — routes that start from a logged-on
       user's credential are invisible in this run.
```

The plain-English layer comes first, so the person who decides whether the work
gets scheduled can read it without knowing what `GenericAll` means. The ranked
paths below it stay precise enough for the engineer who has to make the change.

**A collection gap is never reported as safety.** Every report states what it
could not see. "No path found" because sessions were not collected says exactly
that.

`--report out.html` writes a self-contained report you can send to a client — no
external requests, no fonts, no scripts.

---

## What changed since last time

```
harbinger diff before.dat after.dat
```

Reports both directions: routes that **opened**, with the change responsible for
each, and routes that **closed** — the evidence that a fix actually landed.
Formats may differ on the two sides. Comparing two different directories is
detected and called out rather than silently producing nonsense.

---

## Several clients on one machine

Normal for an MSP, and handled. If an export spans more than one directory,
Harbinger lists every one it found and tells you which it ranked against:

```sh
harbinger analyze forest.dat --domain acme.local
```

Naming a domain that is not present lists the ones that are.

---

## Commands

```sh
harbinger analyze <export> [--report out.html] [--domain d] [--top N]
harbinger diff <t0> <t1>                # what opened, what closed
harbinger check                         # self-test; no file, no network
harbinger gen-testdata [--format=adexplorer|bloodhound] [path]
harbinger help [collecting|privacy|verify]
harbinger version
```

Run `harbinger analyze -h` for the full flag list.

The three documents you need before a first run — how to collect, what leaves
the machine, and how to verify the binary — are **carried inside the
executable**. `harbinger help collecting` prints the full walkthrough offline,
on the machine you are running from, with no checkout and no browser.

---

## Try it without a real directory

```sh
harbinger gen-testdata --format=adexplorer sample.dat
harbinger analyze sample.dat
```

This writes a genuine, valid AD Explorer snapshot containing a known escalation
path — so you can confirm the `.dat` path works on your machine before pointing
the tool at a client's directory.

---

## Building it yourself

The build is reproducible; the same source at the same tag produces
byte-identical output on any machine.

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o harbinger ./cmd/harbinger
go test ./...
```

The tests that matter to a reviewer: `TestNoIdentityLeak` fails the build if any
identifier reaches the outbound payload; `TestLegacyAndCEProduceIdenticalGraphs`
proves old and new BloodHound schemas give the same answer;
`TestCorruptionNeverPanics` sweeps a bit-flip across a whole snapshot file and
asserts the parser never panics.

---

## Documents

| | |
|---|---|
| [DATA_HANDLING.md](docs/DATA_HANDLING.md) | What it reads, what it never does, what leaves (nothing) |
| [COLLECTING.md](docs/COLLECTING.md) | How to get the data, including the EDR warning |
| [VERIFY.md](docs/VERIFY.md) | Signature, checksums, reproducible build |
| [ADEXPLORER.md](docs/ADEXPLORER.md) | Snapshot support: what is extracted, what is not |
| [SIGNING.md](docs/SIGNING.md) | Code-signing setup and release process |
| [PILOT.md](docs/PILOT.md) | Design-partner pilot: shape, duration, what we ask |
| [MUTUAL_NDA.md](docs/MUTUAL_NDA.md) | Mutual NDA template, ready to send |
| [FEEDBACK.md](docs/FEEDBACK.md) | Pre-registered measurement instrument |

---

## License

MIT — see [LICENSE](LICENSE).

Built by [Harbinger Labs](https://harbingerlabs.ai). Scores are structural
priors, not guarantees; "unlikely to be detected" assumes common native and
endpoint telemetry, not your specific tuned EDR.
