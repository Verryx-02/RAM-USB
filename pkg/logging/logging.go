// Package logging provides types and helpers shared across every service to
// keep structured logging (log/slog) safe against two independent risks:
//   - Redacted keeps a login credential from ever being emitted in plaintext
//     (DV-F-03, RD-01).
//   - Sanitize keeps a free-text value that may carry attacker-influenced
//     characters (a validation error that echoes back a malformed request
//     field, for instance) from forging fake log lines or corrupting
//     structured-log parsing when it's written to a log record
//     (RNF-SEC-02/RNF-SEC-03: every layer independently guards its own
//     boundary, including the log sink, rather than trusting that upstream
//     validation already made a value safe to log verbatim).
//
// These are deliberately separate mechanisms: Redacted hides a value
// entirely, Sanitize keeps a value's content but neutralizes the specific
// characters that make it dangerous to write to a log stream.
package logging

import (
	"log/slog"
	"strings"
	"unicode"
)

// Redacted wraps a string that must never appear in plaintext in a log
// record: a login credential such as an email address or a password.
// It implements slog.LogValuer so every slog call (Info, Error, With, ...)
// prints "REDACTED" instead of the wrapped value.
type Redacted string

// LogValue implements slog.LogValuer. It never returns the wrapped string.
func (r Redacted) LogValue() slog.Value {
	return slog.StringValue("REDACTED")
}

// Sanitize returns a copy of s with every Unicode control character
// (unicode.IsControl - newlines, carriage returns, tabs, NUL, and every
// other non-printable byte in that category) replaced with a single space.
// Well-formed printable text is returned unchanged.
//
// Call this on any value passed to a slog call that isn't already a
// compile-time constant when the value's content ultimately traces back to
// external input (a request body, a header, a downstream service's
// response) - most often the formatted string of an error that wraps a
// validation failure. Go's default log/slog TextHandler happens to quote
// strings containing such characters today, but that's the handler's own
// implementation choice, not a guarantee this package should rely on; a
// custom handler or a future stdlib change could remove it.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
