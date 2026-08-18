package cli

import (
	"encoding/json"
	"flag"
	"os"

	"github.com/harbingerlabs/harbinger-cli/internal/features"
)

// parseArgs parses flags that may appear BEFORE or AFTER positional arguments
// (stdlib flag stops at the first positional; users routinely write
// `analyze ./export --report x.html`). Returns the positional args.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	return positional, nil
}

func prettyPayload(req *features.ScoreRequest) string {
	b, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// isTerminal reports whether f is an interactive terminal (for color).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
