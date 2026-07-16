// Package logging provides types shared across every service to keep
// structured logging (log/slog) from ever emitting a login credential in
// plaintext (DV-F-03, RD-01). Any field that could hold an email or a
// password is typed as Redacted, so accidental logging is caught at the
// type level regardless of who writes a new log line.
package logging

import "log/slog"

// Redacted wraps a string that must never appear in plaintext in a log
// record: a login credential such as an email address or a password.
// It implements slog.LogValuer so every slog call (Info, Error, With, ...)
// prints "REDACTED" instead of the wrapped value.
type Redacted string

// LogValue implements slog.LogValuer. It never returns the wrapped string.
func (r Redacted) LogValue() slog.Value {
	return slog.StringValue("REDACTED")
}
