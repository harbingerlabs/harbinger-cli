# Verifying the binary before you run it

You should not run a stranger's executable on a client network without checking
it first. Here is everything you need to do that.

## 1. Check the signature (Windows)

```powershell
Get-AuthenticodeSignature .\harbinger.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

Expect `Status: Valid`, a signer certificate issued to **Harbinger Labs**, and a
non-empty timestamp. Anything else — stop, and tell us.

## 2. Check the checksum

Every release publishes a `SHA256SUMS` file alongside the binaries.

**Windows**
```powershell
Get-FileHash .\harbinger-v0.1.0-windows-amd64.exe -Algorithm SHA256
```

**macOS / Linux**
```sh
sha256sum -c SHA256SUMS --ignore-missing
```

Compare against the line for your file in `SHA256SUMS`. The checksums are
published in the GitHub release, not on a page we can quietly edit.

## 3. Build it yourself (the strongest check)

The build is reproducible: `-trimpath` and `CGO_ENABLED=0` mean the same source
at the same tag produces byte-identical output on any machine.

```sh
git clone https://github.com/harbingerlabs/harbinger-cli
cd harbinger-cli
git checkout v0.1.0
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=v0.1.0" -o harbinger ./cmd/harbinger
sha256sum harbinger
```

That hash should match the published one for your platform (the unsigned
Windows binary will differ from the signed one by exactly the signature block;
Linux and macOS builds match exactly).

## 4. Confirm it does what we say

Two checks, about a second each, no file and no network needed:

```sh
harbinger check
```

Runs the whole pipeline on a synthetic directory and asserts the privacy
invariant end to end: it builds the outbound payload and fails if any name, SID,
or domain string from the graph appears in it.

```sh
harbinger analyze <your-export> --show-payload
```

Prints the exact JSON that hybrid mode *would* transmit. In offline mode it is
built and shown but never sent — which you can confirm independently:

```sh
harbinger analyze <your-export> --offline
```

Run that behind your egress firewall or a packet capture and expect zero
connections.

## 5. Read the code

The client is source available. The file that matters for trust is
`internal/features/features.go` — the single place where information is selected
for possible transmission. If it is not put into a `ScoreRequest` there, it
cannot leave the machine.

---

If any of these checks fail, or a result does not match this document, that is a
bug in the software or the document and we want to hear about it:
security@harbingerlabs.ai
