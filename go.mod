module github.com/harbingerlabs/harbinger-cli

// The Harbinger client is intentionally ZERO-DEPENDENCY (stdlib only).
//
// This is a trust decision, not an accident: a security tool that promises
// "we only ever transmit anonymized structural features" is only auditable if
// the code you have to read to verify that claim is small and self-contained.
// No third-party modules means no transitive supply-chain surface, trivially
// reproducible builds, and a single static binary with nothing to vendor.
go 1.26
