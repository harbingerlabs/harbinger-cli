package cli

import (
	"runtime"
	"testing"
)

// env builds a LookupEnv stand-in from a map.
func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// NO_COLOR is defined by presence, not by value: an empty NO_COLOR still means
// no colour. Every platform, no exceptions.
func TestNoColorWinsEvenWhenEmpty(t *testing.T) {
	for _, m := range []map[string]string{
		{"NO_COLOR": ""},
		{"NO_COLOR": "1"},
		{"NO_COLOR": "", "WT_SESSION": "abc", "TERM": "xterm-256color"},
	} {
		if colorSupported(env(m)) {
			t.Errorf("colour enabled despite NO_COLOR in %v", m)
		}
	}
}

// The case that decides a Windows first impression: a bare cmd.exe advertises
// no VT support, so it must get plain text rather than escape sequences.
func TestWindowsConsoleWithoutVTGetsPlainText(t *testing.T) {
	got := colorSupported(env(map[string]string{}))
	want := runtime.GOOS != "windows"
	if got != want {
		t.Errorf("bare environment: colour = %v, want %v on %s", got, want, runtime.GOOS)
	}
}

// Hosts that do handle ANSI must still get colour — the degradation is for
// consoles that cannot, not for every Windows machine.
func TestVTCapableHostsKeepColor(t *testing.T) {
	for _, m := range []map[string]string{
		{"WT_SESSION": "9f2c"},     // Windows Terminal
		{"ConEmuANSI": "ON"},       // ConEmu
		{"ANSICON": "120x1000"},    // ANSICON
		{"TERM": "xterm-256color"}, // Git Bash / MSYS
	} {
		if !colorSupported(env(m)) {
			t.Errorf("colour disabled for a VT-capable host: %v", m)
		}
	}
}

// TERM=dumb is the long-standing way to say "no capabilities".
func TestDumbTerminalGetsNoColor(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the TERM check only gates the Windows path")
	}
	if colorSupported(env(map[string]string{"TERM": "dumb"})) {
		t.Error("colour enabled for TERM=dumb")
	}
}
