// Package metrics implements Entry-Hub's periodic MQTT metrics publish
// (EH-F-10, EH-F-11): building an aggregated-only payload, an
// mTLS-verified MQTT client to send it, and a once-per-minute scheduling
// loop. It is a deliberate near-duplicate of
// services/security-switch/internal/metrics (itself a near-duplicate of
// services/database-vault/internal/metrics) - same "two isn't enough
// signal to extract a shared pkg/metrics, three is" judgment call already
// documented in those two packages' own doc comments, not re-litigated
// here. Only ServiceName/Topic and the doc-comment requirement IDs
// differ.
package metrics

import (
	"encoding/json"
	"time"
)

// ServiceName is Entry-Hub's identifier in every metrics payload it
// publishes (EH-F-10). Reproduced verbatim from the SRS's literal
// `metrics/Entry-Hub` topic string, not PascalCased the way this
// codebase's mTLS Subject.Organization values are - see
// services/database-vault/internal/metrics/payload.go's identical
// reasoning.
const ServiceName = "Entry-Hub"

// Topic is Entry-Hub's dedicated MQTT publish topic (EH-F-10), reproduced
// verbatim from the SRS's literal `metrics/Entry-Hub` quote.
const Topic = "metrics/" + ServiceName

// Counters holds the already-computed aggregate values a metrics payload
// reports for one publish interval.
type Counters struct {
	// RequestCount is the number of requests handled in the interval.
	RequestCount int64
	// ErrorCount is the number of those requests that resulted in an
	// error response.
	ErrorCount int64
	// AverageResponseTimeMs is the mean response time, in milliseconds,
	// across RequestCount requests in the interval (MT-F-04).
	AverageResponseTimeMs float64
	// ActiveConnections is a point-in-time count of open connections at
	// publish time (MT-F-04).
	ActiveConnections int64
}

// Payload is the exact JSON shape published to Topic every minute
// (EH-F-10). Every field is a count, an average, or a timestamp - never
// an email, username, IP address, or any other per-user value -
// satisfying EH-F-11's "aggregated statistics only, never personal data"
// constraint by construction, same invented-but-documented judgment call
// as Database-Vault's/Security-Switch's identical Payload shape.
type Payload struct {
	Service               string  `json:"service"`
	Timestamp             string  `json:"timestamp"`
	RequestCount          int64   `json:"request_count"`
	ErrorCount            int64   `json:"error_count"`
	AverageResponseTimeMs float64 `json:"average_response_time_ms"`
	ActiveConnections     int64   `json:"active_connections"`
}

// BuildPayload converts already-computed counters into the JSON bytes
// published to Topic. now is taken as an explicit parameter so tests can
// assert an exact timestamp value.
func BuildPayload(counters Counters, now time.Time) ([]byte, error) {
	payload := Payload{
		Service:               ServiceName,
		Timestamp:             now.UTC().Format(time.RFC3339),
		RequestCount:          counters.RequestCount,
		ErrorCount:            counters.ErrorCount,
		AverageResponseTimeMs: counters.AverageResponseTimeMs,
		ActiveConnections:     counters.ActiveConnections,
	}

	return json.Marshal(payload)
}
