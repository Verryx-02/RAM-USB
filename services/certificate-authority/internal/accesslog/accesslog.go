// Package accesslog reads step-ca's own structured JSON access-log lines
// (CA-F-03) and extracts exactly the two fields the metrics sidecar needs:
// status and duration-ns. step-ca (the underlying product backing
// Certificate-Authority) has no native /metrics endpoint - this is the
// documented, verified workaround: enable its "logger": {"format": "json"}
// config (see deployments/compose/certificate-authority.yml's
// certificate-authority-config-init step and
// third-party/certificate-authority/enable-json-logger.sh) and derive
// RequestCount/ErrorCount/AverageResponseTimeMs from the resulting lines.
//
// # RD-01: the sensitive fields this package must never expose
//
// A step-ca "/sign" request's log line additionally carries "ott" (the
// single-use CA-F-04 bootstrap token, in cleartext), "certificate" (the
// full issued certificate, base64 DER), "subject", "sans", "issuer", and
// "provisioner" - none of which this sidecar may ever persist, re-log,
// forward, or publish (RD-01, applied here to a bootstrap token that would
// otherwise sit in cleartext in the Certificate-Authority's own log
// stream). ParseLine enforces this by construction, not by convention: its
// decode target (entryFields) declares only a "status" and a "duration-ns"
// json tag, so encoding/json.Unmarshal has no field to populate any other
// key into - "ott"/"certificate"/"subject"/"sans"/"issuer"/"provisioner"
// are silently dropped by the decoder itself before this package's own code
// ever runs, the same guarantee a hand-written field-by-field filter over a
// map[string]any could not offer as cheaply or as verifiably. See
// accesslog_test.go's own RD-01 test for the live proof: a full real
// "/sign" log line in, only Status/DurationNs out.
package accesslog

import "encoding/json"

// Entry is the only data ParseLine ever extracts from one step-ca
// access-log line - see this package's own doc comment for why no other
// field exists here.
type Entry struct {
	// Status is the HTTP status code of the request this log line
	// describes.
	Status int
	// DurationNs is the request's duration, in nanoseconds.
	DurationNs int64
}

// entryFields is ParseLine's encoding/json decode target - the literal
// enforcement mechanism for this package's RD-01 guarantee (see the
// package doc comment). It carries a struct tag for "status" and
// "duration-ns" only, matching step-ca's own confirmed field names, and no
// other step-ca log field - encoding/json.Unmarshal drops every key with
// no matching struct field, including every field a "/sign" line adds
// (ott, certificate, subject, sans, issuer, provisioner).
type entryFields struct {
	Status     int   `json:"status"`
	DurationNs int64 `json:"duration-ns"`
}

// ParseLine decodes one step-ca access-log line (already stripped of its
// trailing newline) into an Entry. ok is false, with a nil error, when line
// is valid JSON but is not an access-log line this package can derive a
// metric from (e.g. its "status" field is absent or zero - no real HTTP
// response ever carries status 0). err is non-nil only for a genuine JSON
// syntax error (e.g. step-ca's own plain-text startup banner lines, which
// share this same log stream - see
// deployments/compose/certificate-authority.yml's tee-based log capture).
// Both cases are the caller's cue to skip the line, never to log its raw
// content (RD-01).
func ParseLine(line []byte) (entry Entry, ok bool, err error) {
	var fields entryFields
	if err := json.Unmarshal(line, &fields); err != nil {
		return Entry{}, false, err
	}
	if fields.Status == 0 {
		return Entry{}, false, nil
	}
	return Entry(fields), true, nil
}
