# Code signing — the blocking item

**Status: not done. This is the one item that silently kills the launch, and the
one with a calendar dependency you cannot compress. Start it before you write
the first email.**

It gates **Windows only**. Design partners on macOS and Linux can start today on
the build-from-source path in [VERIFY.md](VERIFY.md).

## Why this is blocking, not cosmetic

An MSP's entire job is telling clients not to run unsigned executables from
strangers. If Harbinger arrives unsigned, three things happen, in this order:

1. **SmartScreen** shows "Windows protected your PC" and hides the Run button
   behind *More info*. Most people stop here.
2. **Their EDR** quarantines it. An unsigned, never-before-seen binary that
   enumerates a directory is exactly the shape of a threat.
3. **Their own policy** forbids it. Even an engineer who personally trusts you
   cannot run it without writing an exception, and writing an exception for a
   stranger's tool is a conversation they will decline to have.

None of this produces a reply saying "your binary was blocked." It produces
silence, and silence reads as disinterest. That is why this is the item most
likely to kill the launch without you finding out.

## What to buy — Azure Artifact Signing

Formerly called **Trusted Signing**; renamed in 2026, and the old name still
appears in a lot of third-party write-ups.

| | |
|---|---|
| Cost | **$9.99/month** (Basic: 5,000 signatures, one certificate profile of each type), plus an Azure subscription |
| Premium | $99.99/month (100,000 signatures) — not needed; a release signs six files |
| Overage | $0.005 per signature beyond quota |
| Hardware | None. Keys live in Azure; nothing to ship, nothing to lose |
| SmartScreen | Inherits Microsoft's reputation service; new-publisher warnings clear quickly |
| CI | Already wired in `.github/workflows/harbinger-cli-release.yml` at the repository root |

### Which identity validation

This is the decision that determines everything, and it is worth getting right
before spending anything.

|  | Organization | **Individual developer** |
|---|---|---|
| Certificate says | the company | your legal name, city and state |
| Age requirement | **3+ years** of verifiable operating history | none |
| Where | US, Canada, EU, UK, AU, NZ, JP, KR, SG, CH, NO, IL | **US or Canada only** |
| Proof | business registration, DUNS or tax records, domain ownership — all issued within the last 12 months | government photo ID via Verified ID, plus a utility bill or bank statement |
| Time | 1–20 business days | usually much faster |

**We are taking the individual developer path**, because the three-year rule
fails automatically with no exception and no manual override.

The cost is honest and worth stating: the certificate carries a person's name
rather than the company's. A buyer who checks the signature sees an individual.
That is a real dent in a security product's story and it is still enormously
better than unsigned — and moving to an organization certificate later changes
nothing in the workflow except which identity validation the profile points at.
[VERIFY.md](VERIFY.md) tells buyers what name to expect, so keep the two in step.

## Setting it up

1. **Register the resource provider.** Azure portal → your subscription →
   Resource providers → `Microsoft.CodeSigning` → Register. Or:
   ```sh
   az provider register --namespace Microsoft.CodeSigning
   az extension add --name artifact-signing
   ```
2. **Create an Artifact Signing account**, Basic SKU, in a supported region.
   The endpoint is region-specific — `https://eus.codesigning.azure.net` for
   East US. Note it; it becomes `SIGNING_ENDPOINT`.
   ```sh
   az artifact-signing create -n harbinger -l eastus -g harbinger-rg --sku Basic
   ```
3. **Complete identity validation — portal only.** The CLI cannot do this step,
   and it is the one with the calendar on it. Assign yourself the *Artifact
   Signing Identity Verifier* role first or the **New identity** button stays
   greyed out. Choose **Individual**, then **Public**.

   The form is populated from your Azure **billing account**, read-only. The
   billing account type must be Individual to match, and the legal name and
   address must be exactly what you want on the certificate — a mismatch puts
   the wrong details on it and the only fix is a new validation request. Check
   it before submitting.

   You will verify a government photo ID through a third-party verifier
   (AU10TIX) on a phone, and may be asked for a utility bill or bank statement
   showing the same address. Documents must be recent — typically within three
   months.
4. **Create a certificate profile**, type **Public Trust**. Its name becomes
   `SIGNING_PROFILE`.
5. **Create a service principal with federated credentials** for GitHub Actions,
   scoped to this repository. Federated means no long-lived secret in the repo —
   the workflow authenticates with `azure/login@v2` and the signing action
   inherits that credential.
6. **Add the secrets** below, then publish a GitHub Release. The workflow signs,
   timestamps, verifies the signature actually applied, and publishes
   `SHA256SUMS`.

## Required repository secrets

The release workflow refuses to publish without these. It fails loudly rather
than shipping an unsigned binary.

| Secret | What it is |
|---|---|
| `AZURE_CLIENT_ID` | Service principal (federated credential) |
| `AZURE_TENANT_ID` | Microsoft Entra tenant |
| `AZURE_SUBSCRIPTION_ID` | Subscription holding the signing account |
| `SIGNING_ENDPOINT` | Region endpoint, e.g. `https://eus.codesigning.azure.net` |
| `SIGNING_ACCOUNT` | Artifact Signing account name |
| `SIGNING_PROFILE` | Certificate profile name |

## Before the certificate issues

Do not ask anyone to click through a SmartScreen warning. The credible interim
position is to offer the source build instead:

> The Windows binary is going through code-signing certification now and will be
> signed by <date>. Until then, the client is source-available and builds
> reproducibly — you can build it yourself in one command and check it against
> the published checksum. I would not ask you to run an unsigned binary on a
> client network, and I am not asking now.

You can also produce unsigned builds for your own testing with the release
workflow's `dry_run` input. They are labelled *UNSIGNED — do not distribute* and
uploaded as a workflow artifact rather than a release, on purpose.

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

## Sources

Requirements and pricing move. These were checked on 2026-08-19:
[quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) ·
[pricing](https://azure.microsoft.com/en-us/pricing/details/artifact-signing/) ·
[action](https://github.com/Azure/artifact-signing-action)
