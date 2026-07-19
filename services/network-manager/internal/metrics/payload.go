// Package metrics implements Network-Manager's periodic MQTT metrics
// publish (NM-F-17, NM-F-18): building an aggregated-only payload, an
// mTLS-verified MQTT client to send it, and a once-per-minute scheduling
// loop. Same shape as Database-Vault's internal/metrics (DV-F-16/17) and
// Security-Switch's own equivalent package - see this package's
// individual files for what, if anything, differs.
//
// It does not gather real live statistics from a running server -
// BuildPayload accepts already-computed Counters, exactly like every
// other service's metrics package - cmd/network-manager/main.go supplies
// the real counter source.
package metrics

import (
	"encoding/json"
	"time"
)

// ServiceName is Network-Manager's identifier in every metrics payload it
// publishes (NM-F-17). Reproduced verbatim from the SRS's literal
// `metrics/Network-Manager` topic string, same reasoning as Database-
// Vault's own ServiceName constant: Metrics-Collector (MT-F-02) discards
// any message whose "service" field does not match the MQTT topic it
// arrived on.
const ServiceName = "Network-Manager"

// Topic is Network-Manager's dedicated MQTT publish topic (NM-F-17),
// reproduced verbatim from the SRS's literal `metrics/Network-Manager`
// quote.
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
// (NM-F-17). Every field is a count, an average, or a timestamp - never
// an email, node ID, IP address, or any other per-user/per-node value -
// satisfying NM-F-18's "aggregated statistics only, never personal data"
// constraint by construction. Same invented-but-documented field set as
// Database-Vault's own Payload (no SRS/design document specifies more
// than "aggregated statistics" beyond MT-F-04's dashboard examples).
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
