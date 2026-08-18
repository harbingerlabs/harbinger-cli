# Quickstart

A result in under ten minutes. One executable — no install, no runtime, no admin
rights.

## 1. Get the binary and check it

Download for your platform from the
[releases page](https://github.com/harbingerlabs/harbinger-cli/releases).

**Windows** — verify the signature and checksum before running it:

```powershell
Get-AuthenticodeSignature .\harbinger.exe | Format-List Status, SignerCertificate
Get-FileHash .\harbinger.exe -Algorithm SHA256
```

**macOS / Linux**

```sh
sha256sum -c SHA256SUMS --ignore-missing
chmod +x harbinger-*-darwin-arm64
mv harbinger-*-darwin-arm64 /usr/local/bin/harbinger
```

Full verification options, including a reproducible build you can compare
against: **[VERIFY.md](VERIFY.md)**.

Or build it yourself (Go 1.26+):

```sh
git clone https://github.com/harbingerlabs/harbinger-cli
cd harbinger-cli
make build         # -> bin/harbinger
```

## 2. Prove it works, before touching real data

```sh
harbinger check
```

Runs the whole pipeline on a synthetic directory, exercises the AD Explorer
snapshot reader, and asserts the privacy invariant end to end. About a second,
no file and no network needed.

Then try it on a sample directory:

```sh
harbinger gen-testdata --format=adexplorer sample.dat
harbinger analyze sample.dat
```

You should see a ranked route from a low-privilege user to Domain Admins, a
per-route likelihood that monitoring would miss it, and a single top fix.

## 3. Collect from a real directory

**Read [COLLECTING.md](COLLECTING.md) first** — it takes five minutes and covers
the thing that surprises people: SharpHound will very likely trip your EDR.

Not at a browser? The same walkthrough is inside the binary:

```sh
harbinger help collecting
```

The short version: use **AD Explorer** (Microsoft Sysinternals, already trusted
in a Windows shop), `File → Create Snapshot`, wait for it to finish, then:

```sh
harbinger analyze C:\temp\client-2026-08-14.dat --report client.html
```

Already have a BloodHound export? Point at it directly — `.zip`, a folder of
`.json`, or a single `.json`, in either the CE or the older Legacy schema.

This is **fully offline**. Nothing leaves your machine.

## 4. The flags worth knowing

```sh
harbinger analyze export --report exposure.html   # self-contained, sendable, prints well
harbinger analyze export --json > result.json     # structured output (see below)
harbinger analyze export --domain acme.local      # pick one directory of several
harbinger analyze export --top 20                 # show more routes
harbinger analyze export --max-starts 5000        # bound the search on a big directory
harbinger analyze export --show-payload           # audit what hybrid mode WOULD send
harbinger diff before.dat after.dat               # what opened, and what your fix closed
```

## 5. The second run is the point

Take a snapshot, make the top fix, take another snapshot:

```sh
harbinger diff before.dat after.dat
```

It reports routes that opened **and** routes that closed — the evidence the fix
landed, which is what you show the client.

## 6. (Optional) hybrid scoring

If you have an API key and want the calibrated hosted model instead of the local
distilled one:

```sh
harbinger analyze export --api-key hbk_live_xxx
```

Only anonymized, tokenized structural features are sent. Verify exactly what
that means with `--show-payload` first, and read
[DATA_HANDLING.md](DATA_HANDLING.md).

## Exit codes

`0` success · `1` runtime error (unreadable export, scoring failure) · `2` usage error.

## Wiring it into your PSA or RMM

`--json` writes a versioned envelope, so a script can assert on the shape before
trusting it:

```json
{
  "schema": "harbinger.analysis/1",
  "client": "distilled-1.0.0",
  "result": {
    "crown_name": "DOMAIN ADMINS@CORP.LOCAL",
    "paths": [
      {
        "rank": 1,
        "risk": 0.703,
        "hops": 1,
        "evasion": 0.72,
        "blind_spot": true,
        "start_count": 3,
        "target_name": "CORP.LOCAL",
        "steps": [{"from_name": "svc-scanner@CORP.LOCAL", "to_name": "CORP.LOCAL", "edge": "DCSync"}]
      }
    ],
    "top_fix": {"from_name": "…", "to_name": "…", "edge": "DCSync", "paths_killed": 3}
  }
}
```

`start_count` is how many principals can walk that same route — every member of
the group holding the permission produces an identical route with an identical
fix, so they are reported once, with a count.

**Check `schema` and fail loudly if it is not the version you built against.**
`harbinger diff --json` uses `harbinger.diff/1` with the same envelope. Within a
major version, fields may be added and never removed or renamed.
