// Package metrics implements Security-Switch's periodic MQTT metrics
// publish (SS-F-07, SS-F-08): building an aggregated-only payload, an
// mTLS-verified MQTT client to send it, and a once-per-minute scheduling
// loop. It does not gather real live statistics from a running server -
// no cmd/security-switch/main.go or HTTP handler wiring exists yet to
// count real requests - so BuildPayload accepts already-computed
// Counters, exactly like Database-Vault's internal/metrics package
// (DV-F-16, DV-F-17) does. Wiring a real counter source and calling Run
// from cmd/security-switch/main.go is a later task.
//
// This package is a deliberate near-duplicate of
// services/database-vault/internal/metrics, not a shared pkg/metrics
// extraction. Judgment call, documented here rather than silently made:
// this codebase's established convention (CONTRIBUTING.md §7's package
// layout, and Database-Vault's own hashing/encryption/registration/login
// packages) keeps service-specific business logic under each service's
// own internal/, promoting only genuinely cross-service logic to pkg/
// (mtls, errors, logging, validation - all things every service calls
// identically with no service-specific parameter beyond a string
// constant). This metrics package differs from those pkg/ candidates in
// one way that matters: Counters/Payload/ServiceName/Topic are themselves
// service-specific values (a Security-Switch payload is not a
// parameterized instance of a generic "any service's metrics" type, it's
// this service's own aggregate). Extracting a shared pkg/metrics now,
// before a third consumer (Storage-Service, ST-F-12/13; Network-Manager,
// NM-F-17/18) exists to confirm what actually varies vs. what's
// incidental duplication, risks guessing at the wrong abstraction boundary
// - the same premature-abstraction risk this project avoids elsewhere.
// Revisit this decision once a third service needs the identical shape:
// three real instances give enough signal to extract confidently.
package metrics

import (
	"encoding/json"
	"time"
)

// ServiceName is Security-Switch's identifier in every metrics payload it
// publishes (SS-F-07). Reproduced verbatim from the SRS's literal
// `metrics/Security-Switch` topic string, not PascalCased the way this
// codebase's mTLS Subject.Organization values are - see
// services/database-vault/internal/metrics/payload.go's identical
// reasoning.
const ServiceName = "Security-Switch"

// Topic is Security-Switch's dedicated MQTT publish topic (SS-F-07),
// reproduced verbatim from the SRS's literal `metrics/Security-Switch`
// quote.
const Topic = "metrics/" + ServiceName

// Counters holds the already-computed aggregate values a metrics payload
// reports for one publish interval. See the package doc comment for why
// gathering these from live traffic is out of this package's scope.
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
// (SS-F-07). Every field is a count, an average, or a timestamp - never
// an email, username, IP address, or any other per-user value -
// satisfying SS-F-08's "aggregated statistics only, never personal data"
// constraint by construction, same invented-but-documented judgment call
// as Database-Vault's identical Payload shape (DV-F-16/17).
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
