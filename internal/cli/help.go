package cli

import (
	"fmt"
	"io"
	"strings"

	harbinger "github.com/harbingerlabs/harbinger-cli"
)

// topic is one piece of operator documentation carried inside the binary.
type topic struct {
	name    string
	summary string
	body    func() string
}

// topics are the questions an operator has to answer before a first run, in the
// order they hit them: how do I get the data, is it safe to run, and can I trust
// the executable. Each is answerable offline, from the binary, with no
// repository checkout and no browser.
var topics = []topic{
	{"collecting", "how to get an export (start here — covers the EDR warning)", func() string { return harbinger.Collecting }},
	{"privacy", "what is read, what never happens, what leaves the machine", func() string { return harbinger.DataHandling }},
	{"verify", "check the binary before running it on a client network", func() string { return harbinger.Verify }},
}

// Help prints top-level usage, or one embedded document when a topic is named.
func Help(w io.Writer, args []string) int {
	if len(args) == 0 {
		Usage(w)
		helpTopics(w)
		return 0
	}
	want := strings.ToLower(strings.TrimSpace(args[0]))
	for _, t := range topics {
		if t.name == want {
			fmt.Fprint(w, t.body())
			return 0
		}
	}
	fmt.Fprintf(w, "no help topic %q.\n", want)
	helpTopics(w)
	return 2
}

// helpTopics lists what is readable offline from the binary itself.
func helpTopics(w io.Writer) {
	fmt.Fprint(w, "\nHELP TOPICS  (full text, offline, inside this binary)\n")
	for _, t := range topics {
		fmt.Fprintf(w, "  harbinger help %-12s %s\n", t.name, t.summary)
	}
}
