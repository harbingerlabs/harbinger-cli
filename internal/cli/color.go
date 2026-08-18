package cli

import "runtime"

// colorSupported reports whether ANSI escapes will render as colour rather than
// as literal garbage.
//
// This matters more here than it looks. The buyers are Windows shops, and on
// Windows the console does not interpret ANSI escapes unless the host turned
// virtual-terminal processing on. Windows Terminal does; the classic conhost
// behind cmd.exe does not, and a first run there prints the whole report
// interleaved with sequences like "<-[36m". That is the first thing a design
// partner would see.
//
// Two ways to get this wrong. Enabling VT processing ourselves means a kernel32
// call we cannot test from here, on the one platform we cannot run. Assuming it
// works means garbage on the default console. So we detect instead: colour only
// where the host advertises that it handles it. Plain text on an older console
// is a graceful degradation — escape codes are not.
//
// look is os.LookupEnv, taken as a parameter so this is testable without
// touching the process environment.
func colorSupported(look func(string) (string, bool)) bool {
	// NO_COLOR: presence disables colour, whatever the value. Cross-platform
	// convention (https://no-color.org), honoured because operators pipe this
	// into ticketing systems and logs.
	if _, set := look("NO_COLOR"); set {
		return false
	}
	if runtime.GOOS != "windows" {
		return true
	}
	// Windows hosts that do interpret ANSI, each identified by a variable it
	// sets itself: Windows Terminal, ConEmu, ANSICON, and the MSYS/Cygwin
	// terminals behind Git Bash (which set TERM the way a Unix shell does).
	for _, key := range []string{"WT_SESSION", "ConEmuANSI", "ANSICON", "TERM"} {
		if v, set := look(key); set && v != "" && v != "dumb" {
			return true
		}
	}
	return false
}
