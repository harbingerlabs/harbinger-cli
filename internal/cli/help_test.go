package cli

import (
	"bytes"
	"strings"
	"testing"
)

// The operator has one executable and nothing else. Every topic must render
// real content from inside the binary — an empty topic means the guidance did
// not get embedded and the operator is stranded at the collection step.
func TestEveryHelpTopicHasEmbeddedContent(t *testing.T) {
	for _, tc := range topics {
		var b bytes.Buffer
		if code := Help(&b, []string{tc.name}); code != 0 {
			t.Errorf("help %s: exit %d, want 0", tc.name, code)
		}
		if b.Len() < 500 {
			t.Errorf("help %s: only %d bytes — the document did not embed", tc.name, b.Len())
		}
	}
}

// The collection walkthrough is the one that decides whether an unassisted run
// succeeds. It must carry the EDR warning and the tool we actually recommend.
func TestCollectingHelpCarriesTheWarningThatMatters(t *testing.T) {
	var b bytes.Buffer
	Help(&b, []string{"collecting"})
	got := b.String()
	for _, want := range []string{"AD Explorer", "EDR", "SharpHound"} {
		if !strings.Contains(got, want) {
			t.Errorf("collecting help does not mention %q", want)
		}
	}
}

// A mistyped topic must list the real ones rather than dead-ending.
func TestUnknownTopicListsTheRealOnes(t *testing.T) {
	var b bytes.Buffer
	if code := Help(&b, []string{"collect"}); code != 2 {
		t.Errorf("unknown topic exit = %d, want 2", code)
	}
	for _, tc := range topics {
		if !strings.Contains(b.String(), tc.name) {
			t.Errorf("unknown-topic output does not offer %q", tc.name)
		}
	}
}

// Bare `harbinger help` must advertise that the manual is offline in the
// binary; otherwise nobody discovers it.
func TestBareHelpAdvertisesTheTopics(t *testing.T) {
	var b bytes.Buffer
	if code := Help(&b, nil); code != 0 {
		t.Errorf("bare help exit = %d, want 0", code)
	}
	if !strings.Contains(b.String(), "harbinger help collecting") {
		t.Error("bare help does not point at the collection walkthrough")
	}
}
