// Package harbinger embeds the operator documentation into the binary.
//
// An MSP downloads one executable and nothing else — no repository, no docs
// folder, often no browser open on the machine they are running it from. Telling
// that operator to "read docs/COLLECTING.md" points at a file they do not have,
// and the collection step is exactly where an unassisted run fails.
//
// So the guidance that decides whether a collection succeeds ships inside the
// binary and is readable offline, at the moment it is needed. These are the same
// files served on GitHub — embedded, not duplicated, so they cannot drift.
package harbinger

import _ "embed"

// Collecting is the walkthrough for getting an export out of a directory,
// including the EDR warning that surprises people.
//
//go:embed docs/COLLECTING.md
var Collecting string

// DataHandling is the one-page statement of what is read, what is never done,
// and what leaves the machine.
//
//go:embed docs/DATA_HANDLING.md
var DataHandling string

// Verify is how to check the binary before running it on a client network.
//
//go:embed docs/VERIFY.md
var Verify string
