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

	"github.com/harbingerlabs/harbinger-cli/internal/cli"
)

// Version is overridden at build time via -ldflags "-X main.Version=...".
var Version = "0.1.0-dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		cli.Usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "analyze":
		return cli.CmdAnalyze(args[1:], Version)
	case "diff":
		return cli.CmdDiff(args[1:], Version)
	case "check":
		return cli.CmdCheck(args[1:], Version)
	case "gen-testdata":
		return cli.CmdGenTestdata(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("harbinger %s  (feature schema %s)\n", Version, cli.SchemaVersion())
		return 0
	case "help", "--help", "-h":
		return cli.Help(os.Stdout, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		cli.Usage(os.Stderr)
		return 2
	}
}
