package accesslog

import (
	"strings"
	"testing"
)

// Requirement: CA-F-03
func TestParseLine_ExtractsStatusAndDuration(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantEntry Entry
		wantOK    bool
		wantErr   bool
	}{
		{
			name:      "real /health line",
			line:      `{"duration":"89.042µs","duration-ns":89042,"level":"info","method":"GET","msg":"","name":"ca","path":"/health","protocol":"HTTP/2.0","referer":"","remote-address":"::1","request-id":"d2cf8e4b","size":16,"status":200,"time":"2026-07-24T13:42:58Z","user-agent":"Smallstep CLI/0.30.2","user-id":""}`,
			wantEntry: Entry{Status: 200, DurationNs: 89042},
			wantOK:    true,
		},
		{
			name:      "error status",
			line:      `{"duration-ns":1500000,"status":500}`,
			wantEntry: Entry{Status: 500, DurationNs: 1500000},
			wantOK:    true,
		},
		{
			name:   "status absent - not an access-log line",
			line:   `{"duration-ns":1500000}`,
			wantOK: false,
		},
		{
			name:   "status explicitly zero",
			line:   `{"status":0,"duration-ns":100}`,
			wantOK: false,
		},
		{
			name:    "plain-text startup banner sharing the same log stream",
			line:    `2026/07/24 13:42:54 Serving HTTPS on :9000 ...`,
			wantErr: true,
		},
		{
			name:    "empty line",
			line:    ``,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, ok, err := ParseLine([]byte(tt.line))

			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseLine(%q) err = nil, want non-nil", tt.line)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLine(%q) unexpected err = %v", tt.line, err)
			}
			if ok != tt.wantOK {
				t.Fatalf("ParseLine(%q) ok = %v, want %v", tt.line, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if entry != tt.wantEntry {
				t.Fatalf("ParseLine(%q) = %+v, want %+v", tt.line, entry, tt.wantEntry)
			}
		})
	}
}

// Requirement: RD-01
//
// A real "/sign" log line carries "ott" (the CA-F-04 bootstrap token, in
// cleartext), "certificate" (the full issued certificate), "subject",
// "sans", "issuer", and "provisioner" - none of which may ever reach a
// value this package returns to its caller. This test decodes a line
// carrying every one of those fields and asserts the returned Entry has no
// way to have captured any of them: Entry has exactly two fields
// (Status/DurationNs), so the compiler itself, not a runtime check, is
// what makes this assertion meaningful.
func TestParseLine_SignLineNeverExposesSensitiveFields(t *testing.T) {
	// A representative /sign log line, field names confirmed live against
	// a real step-ca container (see this package's own doc comment).
	line := `{"duration-ns":250000,"status":201,"path":"/1.0/sign","method":"POST","name":"ca","ott":"eyJhbGciOiJFUzI1NiJ9.super-secret-bootstrap-token.signature","certificate":"MIIBxTCCAWugAwIBAgIRAKrand0mBase64EncodedDER==","subject":"EntryHub","sans":["EntryHub"],"issuer":"RAM-USB Dev CA Intermediate CA","provisioner":{"name":"admin"}}`

	entry, ok, err := ParseLine([]byte(line))
	if err != nil {
		t.Fatalf("ParseLine unexpected err = %v", err)
	}
	if !ok {
		t.Fatalf("ParseLine ok = false, want true (status=201 present)")
	}
	if entry.Status != 201 || entry.DurationNs != 250000 {
		t.Fatalf("entry = %+v, want {Status:201 DurationNs:250000}", entry)
	}

	// Entry has exactly two fields (Status/DurationNs, both already
	// asserted above) - there is no field here any of "ott"/"certificate"/
	// "subject"/"sans"/"issuer"/"provisioner" could have been assigned
	// into, enforced by the compiler, not a runtime check. This loop is a
	// belt-and-braces sanity check confirming the test's own input line
	// genuinely carries every one of those sensitive field names (i.e.
	// this test would fail to compile-time-guarantee anything if the line
	// above were ever edited to stop containing them).
	for _, sensitive := range []string{"ott", "certificate", "subject", "sans", "issuer", "provisioner", "secret", "MIIB"} {
		if strings.Contains(line, sensitive) == false {
			t.Fatalf("test setup error: line does not contain %q", sensitive)
		}
	}
}
