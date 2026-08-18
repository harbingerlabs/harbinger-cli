package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/harbingerlabs/harbinger-cli/internal/parse"
)

func countStr(r *parse.Report) string {
	if r == nil || len(r.Counts) == 0 {
		return "0 objects"
	}
	type kv struct {
		k parse.Kind
		v int
	}
	var items []kv
	total := 0
	for k, v := range r.Counts {
		if v == 0 || k == parse.KindUnknown {
			continue
		}
		items = append(items, kv{k, v})
		total += v
	}
	sort.Slice(items, func(i, j int) bool { return items[i].v > items[j].v })
	var parts []string
	for _, it := range items {
		parts = append(parts, fmt.Sprintf("%d %s", it.v, strings.ToLower(string(it.k))))
	}
	return fmt.Sprintf("%d objects (%s)", total, strings.Join(parts, ", "))
}

// wrapText hard-wraps prose at width columns on word boundaries, so the
// plain-English layer stays readable in an 80-column terminal.
func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > width {
			lines = append(lines, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	return append(lines, cur)
}

func danglingStr(r *parse.Report) string {
	if r == nil || r.Dangling == 0 {
		return ""
	}
	return fmt.Sprintf(" [%d dangling refs tolerated]", r.Dangling)
}
