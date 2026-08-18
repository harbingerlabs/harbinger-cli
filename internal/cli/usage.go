package cli

import (
	"fmt"
	"io"
)

// Usage prints top-level help, including the plain-language data-handling note.
func Usage(w io.Writer) {
	fmt.Fprint(w, `harbinger — local Active Directory attack-path analysis

USAGE
  harbinger analyze <export>            rank routes to Domain Admin + the top fix
  harbinger diff <t0> <t1>              what changed: routes opened and closed
  harbinger check                       self-test (no file, no network needed)
  harbinger gen-testdata [dir|file]     write a sample export to try it on
  harbinger help <topic>                the manual, offline, inside this binary
  harbinger version                     print client + schema version

WHAT <export> CAN BE  (the format is detected, the extension is not trusted)
  • An AD Explorer snapshot: .dat  ← recommended; harbinger help collecting
  • A BloodHound export: .zip, a folder of *.json, or a single .json
  • Both BloodHound CE and Legacy/older SharpHound schemas are supported.

COLLECTING THE DATA
  Most Windows admins have never run SharpHound, and running it will very likely
  trip your EDR — attackers use the same tool. Sysinternals AD Explorer is signed
  by Microsoft, is already trusted in a Windows shop, and Harbinger reads its
  snapshots directly with no converter and no Python.
      Run 'harbinger help collecting' before you collect anything — the full
      walkthrough is inside this binary, so you do not need this page or a
      browser on the machine you are running from.

WHAT IT READS / WHAT LEAVES  (the whole trust story)
  • Reads: one local export file. READ-ONLY.
  • Never: touches live AD, uses credentials, or runs a collection itself.
  • Default is OFFLINE: zero network calls, nothing leaves this machine.
  • Hybrid mode (only if you pass --api-key) transmits ONLY anonymized, tokenized
    structural features — never names, SIDs, GUIDs, SPNs, or descriptions.
    Verify exactly what would be sent with:  harbinger analyze <export> --show-payload
  • No telemetry. No licence check. No update beacon.

COMMON FLAGS
  --offline            force fully-local scoring (zero network) — this is the default
  --api-key <key>      opt in to hybrid scoring with the server model
  --show-payload       print the exact tokenized payload before/instead of sending
  --domain <name|SID>  restrict to one directory when the export holds several
  --json               structured JSON to stdout
  --report out.html    write a shareable, self-contained report (.html or .md)
  --hvt a,b            designate extra High-Value Targets (SIDs or names)
  --top N              routes to show (default 10)
  --quiet / --verbose  less / more diagnostics

  Run 'harbinger analyze -h' or 'harbinger diff -h' for the full flag list.
  Data-handling statement: 'harbinger help privacy' · harbingerlabs.ai
`)
}

func analyzeUsage(w io.Writer) {
	fmt.Fprint(w, `harbinger analyze <export> [flags]

  <export>  an AD Explorer snapshot (.dat), a BloodHound .zip, a folder of
            *.json, or a single .json. The format is detected from the file's
            contents, so a renamed file still works.

FLAGS
  --offline            score locally, zero network (default when no --api-key)
  --api-key <key>      opt in to hybrid server scoring (env HARBINGER_API_KEY)
  --api-url <url>      override server base URL (env HARBINGER_API_URL)
  --show-payload       print the exact tokenized payload (audit) then continue
  --domain <name|SID>  analyze one directory when the export spans several
  --json               structured JSON to stdout
  --report <file>      write .html or .md shareable report
  --hvt a,b            extra High-Value Targets (SIDs or names)
  --top N              routes to show (default 10)
  --max-hops N         max path length (default 12)
  --k-paths N          k-shortest paths to the crown (default 15)
  --max-starts N       cap low-priv starts on very large graphs (0 = all)
  --verbose/--quiet    more/less diagnostics ; --no-color (or NO_COLOR=1) disables ANSI

EXAMPLES
  harbinger analyze snapshot.dat
  harbinger analyze bloodhound.zip --report client-report.html
  harbinger analyze forest.dat --domain clientb.local
`)
}

func diffUsage(w io.Writer) {
	fmt.Fprint(w, `harbinger diff <t0> <t1> [flags]

  <t0> <t1>  two exports of the SAME directory, earlier then later. Formats may
             differ (compare a .dat against a BloodHound export if you like).

  Reports both directions:
    • routes to the crown that OPENED since t0, and the change that opened each
    • routes that CLOSED since t0 — the evidence a fix actually landed

  Comparing two different directories is detected and called out rather than
  silently producing nonsense. Use --domain to pin one directory on both sides.

  Flags are the same as 'analyze'.
`)
}
