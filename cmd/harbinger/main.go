// Command harbinger is the open-source Harbinger client: it reads a local
// BloodHound/SharpHound export and reports which attack paths to Domain Admin
// are likely to evade current detection.
//
// Privacy posture (default): OFFLINE. Nothing leaves the machine unless you pass
// an --api-key to opt into hybrid scoring, and even then ONLY anonymized,
// tokenized structural features are sent (inspect them with --show-payload).
package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/harbingerlabs/harbinger-cli/internal/cli"
)

// Version is stamped at release time via -ldflags "-X main.Version=...".
// Left empty so that a build without it can fall back to the module version.
var Version = ""

// version reports what this binary should call itself.
//
// Release builds stamp it through ldflags. `go install ...@v0.1.0` cannot —
// it compiles from the module cache with no linker flags — so without a
// fallback every installed copy called itself "0.1.0-dev" no matter which tag
// the user asked for. The module version recorded in the build info is the
// right answer there, and it is the one Go itself already knows.
func version() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		cli.Usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "analyze":
		return cli.CmdAnalyze(args[1:], version())
	case "diff":
		return cli.CmdDiff(args[1:], version())
	case "check":
		return cli.CmdCheck(args[1:], version())
	case "gen-testdata":
		return cli.CmdGenTestdata(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("harbinger %s  (feature schema %s)\n", version(), cli.SchemaVersion())
		return 0
	case "help", "--help", "-h":
		return cli.Help(os.Stdout, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		cli.Usage(os.Stderr)
		return 2
	}
}
