// Package metrics implements Database-Vault's periodic MQTT metrics
// publish (DV-F-16, DV-F-17): building an aggregated-only payload, an
// mTLS-verified MQTT client to send it, and a once-per-minute scheduling
// loop. It does not gather real live statistics from a running server -
// no cmd/database-vault/main.go or HTTP handler exists yet to count real
// requests - so BuildPayload accepts already-computed Counters, exactly
// like DV-F-08 through DV-F-15's orchestration functions accept
// already-computed hashes/ciphertexts rather than deriving them
// internally. Wiring a real counter source and calling Run from
// cmd/database-vault/main.go is a later task.
package metrics

import (
	"encoding/json"
	"time"
)

// ServiceName is Database-Vault's identifier in every metrics payload it
// publishes (DV-F-16). Metrics-Collector (MT-F-02) discards any message
// whose "service" field does not match the MQTT topic it arrived on, so
// this value is deliberately identical to Topic's "metrics/<name>"
// suffix - both are reproduced verbatim from the SRS's literal
// `metrics/Database-Vault` topic string (DV-F-16), not PascalCased the
// way this codebase's mTLS Subject.Organization values are
// ("SecuritySwitch", "StorageService"): those organization strings are
// this codebase's own convention where the SRS gives none, whereas the
// topic name here IS the SRS's literal, quoted value.
const ServiceName = "Database-Vault"

// Topic is Database-Vault's dedicated MQTT publish topic (DV-F-16),
// reproduced verbatim from the SRS's literal `metrics/Database-Vault`
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
// (DV-F-16). Every field is a count, an average, or a timestamp - never
// an email, username, IP address, or any other per-user value -
// satisfying DV-F-17's "aggregated statistics only, never personal
// data" constraint by construction: there is no field here a per-user
// value could be assigned to.
//
// No SRS requirement or design document specifies this payload's exact
// field set beyond "aggregated statistics" (DV-F-17) and MT-F-04's
// example dashboard metrics (response time, throughput, active
// connections). This shape is this session's judgment call, following
// the same "invented but explicitly documented" pattern as DV-F-09's
// invented Storage-Service HTTP contract - revisit if Metrics-Collector's
// real consumption side (not built yet either) ends up needing a
// different shape.
type Payload struct {
	Service               string  `json:"service"`
	Timestamp             string  `json:"timestamp"`
	RequestCount          int64   `json:"request_count"`
	ErrorCount            int64   `json:"error_count"`
	AverageResponseTimeMs float64 `json:"average_response_time_ms"`
	ActiveConnections     int64   `json:"active_connections"`
}

// BuildPayload converts already-computed counters into the JSON bytes
// published to Topic. now is taken as an explicit parameter (rather than
// read internally via time.Now()) so tests can assert an exact timestamp
// value.
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
