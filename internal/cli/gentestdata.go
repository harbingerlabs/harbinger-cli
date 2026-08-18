package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/adexplorer"
	"github.com/harbingerlabs/harbinger-cli/internal/synth"
)

// CmdGenTestdata writes a small synthetic export so a new user can try
// `harbinger analyze` in seconds without a real collection — and, with
// --format=adexplorer, can confirm the .dat path works on their own machine
// before pointing the tool at a client's directory.
func CmdGenTestdata(args []string) int {
	fs := flag.NewFlagSet("gen-testdata", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	filler := fs.Int("filler", 0, "extra unrelated principals (scale test)")
	format := fs.String("format", "bloodhound", "sample format: bloodhound | adexplorer")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return 2
	}

	switch strings.ToLower(*format) {
	case "adexplorer", "adexp", "dat":
		out := "harbinger-sample.dat"
		if len(pos) > 0 {
			out = pos[0]
		}
		if err := adexplorer.SynthWriteFile(out); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Printf("wrote synthetic AD Explorer snapshot to %s\n", out)
		fmt.Printf("try:  harbinger analyze %s\n", out)
		return 0
	case "bloodhound", "bh", "json":
		dir := "harbinger-sample"
		if len(pos) > 0 {
			dir = pos[0]
		}
		if err := synth.WriteDir(dir, *filler); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Printf("wrote synthetic export to %s/\n", dir)
		fmt.Printf("try:  harbinger analyze %s\n", dir)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "error: unknown --format %q (want bloodhound or adexplorer)\n", *format)
		return 2
	}
}
