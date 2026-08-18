# Code signing — the blocking item

**Status: not done. This is the one item that silently kills the launch, and the
one with a calendar dependency you cannot compress. Start it before you write
the first email.**

## Why this is blocking, not cosmetic

An MSP's entire job is telling clients not to run unsigned executables from
strangers. If Harbinger arrives unsigned, three things happen, in this order:

1. **SmartScreen** shows "Windows protected your PC" and hides the Run button
   behind *More info*. Most people stop here.
2. **Their EDR** quarantines it. An unsigned, never-before-seen binary that
   enumerates a directory export is exactly the shape of a threat.
3. **Their own policy** forbids it. Even an engineer who personally trusts you
   cannot run it without writing an exception, and writing an exception for a
   stranger's tool is a conversation they will decline to have.

None of this produces a reply saying "your binary was blocked." It produces
silence, and silence reads as disinterest. That is why this is the item most
likely to kill the launch without you finding out.

## What to buy

Two viable options. Pick one today.

### Option A — Azure Trusted Signing (recommended)

| | |
|---|---|
| Cost | ~$10/month (Basic tier), plus an Azure subscription |
| Time to issue | 1–3 business days for identity validation |
| Hardware | None. Keys live in Azure; nothing to ship or lose |
| SmartScreen | Inherits Microsoft's reputation service; new-publisher warnings clear quickly |
| CI integration | Already wired in `.github/workflows/harbinger-cli-release.yml` |

Requirements: a legal entity that has existed for **3+ years**, or you fall back
to the individual/new-business validation path, which is slower and more
document-heavy. Check this first — it is the most common blocker.

Steps:
1. Azure Portal → create a **Trusted Signing account**.
2. Create a **certificate profile** (Public Trust).
3. Complete identity validation. You will need incorporation documents and a
   verifiable business phone/address (D-U-N-S or equivalent).
4. Create a service principal with **federated credentials** for GitHub Actions
   (no long-lived secret in the repo).
5. Populate the repository secrets in the table below.

### Option B — OV/EV certificate from a CA

DigiCert, Sectigo, SSL.com. Since June 2023 **all** code-signing keys must live
on hardware or a cloud HSM, so an EV cert means either a shipped YubiKey (which
cannot be used from CI without a self-hosted runner) or a cloud signing service
(DigiCert KeyLocker, SSL.com eSigner).

| | |
|---|---|
| Cost | $300–$700/year (OV), $400–$1,000/year (EV) |
| Time to issue | 3 days to 3 weeks. EV validation is slow and picky |
| Hardware | HSM token shipped to you, or a cloud HSM subscription |
| SmartScreen | EV gets instant reputation. OV builds reputation over downloads |

If you go this route, use the cloud-HSM variant, and replace the
`azure/trusted-signing-action` step in the release workflow with the CA's CLI.
The verification step after it does not change and should be kept.

## Required repository secrets

The release workflow refuses to publish without these. It fails loudly rather
than shipping an unsigned binary.

| Secret | What it is |
|---|---|
| `AZURE_CLIENT_ID` | Service principal (federated credential) |
| `AZURE_TENANT_ID` | Entra tenant |
| `AZURE_SUBSCRIPTION_ID` | Subscription holding the signing account |
| `TRUSTED_SIGNING_ENDPOINT` | e.g. `https://eus.codesigning.azure.net` |
| `TRUSTED_SIGNING_ACCOUNT` | Trusted Signing account name |
| `TRUSTED_SIGNING_PROFILE` | Certificate profile name |

## Timestamping is not optional

Every signature is countersigned with an RFC-3161 timestamp
(`http://timestamp.acs.microsoft.com`). Without it, every binary you ever
shipped stops validating the day the certificate expires — including the copy an
MSP archived eighteen months ago. The workflow fails the release if a timestamp
is missing.

## Verifying a signature (send this to a buyer who asks)

```powershell
Get-AuthenticodeSignature .\harbinger.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid` and `TimeStamperCertificate` must not be empty.

## macOS and Linux

Lower priority — MSPs are Windows shops — but for completeness:

- **macOS**: Developer ID certificate ($99/year Apple Developer Program) plus
  notarization via `notarytool`. Without notarization, Gatekeeper blocks it.
- **Linux**: no signing infrastructure to satisfy. The published `SHA256SUMS`
  is the verification story. A detached GPG signature over `SHA256SUMS` is a
  cheap addition if a buyer asks.

## Interim position, if you must email before the certificate issues

Be explicit rather than hoping nobody notices:

> The Windows binary is going through code-signing certification now and will be
> signed by <date>. Until then, the client is source-available and builds
> reproducibly with `go build -trimpath` — you can build it yourself in one
> command and check it against the published checksum. I would not ask you to
> run an unsigned binary on a client network, and I am not asking now.

Offering the source build **instead of** asking them to bypass SmartScreen is
the credible version of this. Asking them to click through the warning is not,
and it costs you the relationship with exactly the buyers who matter most.
