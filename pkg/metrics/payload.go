package metrics

import (
	"encoding/json"
	"time"
)

// TopicFor returns serviceName's dedicated MQTT publish topic, per the
// SRS's literal "metrics/<Service-Name>" convention (e.g. EH-F-10's
// `metrics/Entry-Hub`, DV-F-16's `metrics/Database-Vault`). Every metrics
// requirement across every service (EH-F-10, SS-F-07, DV-F-16, ST-F-12,
// NM-F-17, CA-F-03) derives its topic this same way, so the derivation
// lives here once rather than as a per-service constant.
func TopicFor(serviceName string) string {
	return "metrics/" + serviceName
}

// Counters holds the already-computed aggregate values a metrics payload
// reports for one publish interval. Each service owns its own accumulator
// (e.g. a request/error/response-time counter fed by live traffic) and
// converts it to Counters via a Snapshot method at publish time; this
// package never gathers statistics itself.
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

// Payload is the exact JSON shape published to a service's metrics topic
// every minute (EH-F-10, SS-F-07, DV-F-16, ST-F-12, NM-F-17, CA-F-03).
// Every field is a count, an average, or a timestamp - never an email,
// username, node ID, IP address, or any other per-user/per-node value -
// satisfying each requirement's paired "aggregated statistics only, never
// personal data" constraint (EH-F-11, SS-F-08, DV-F-17, ST-F-13, NM-F-18,
// and CA-F-03's own pairing) by construction: there is no field here a
// per-user value could be assigned to. No SRS requirement or design
// document specifies this payload's exact field set beyond "aggregated
// statistics" plus MT-F-04's example dashboard metrics (response time,
// throughput, active connections); this shape is an invented-but-explicitly-
// documented judgment call, identical across every service that publishes
// it.
type Payload struct {
	Service               string  `json:"service"`
	Timestamp             string  `json:"timestamp"`
	RequestCount          int64   `json:"request_count"`
	ErrorCount            int64   `json:"error_count"`
	AverageResponseTimeMs float64 `json:"average_response_time_ms"`
	ActiveConnections     int64   `json:"active_connections"`
}

// BuildPayload converts serviceName's already-computed counters into the
// JSON bytes published to TopicFor(serviceName). now is taken as an
// explicit parameter (rather than read internally via time.Now()) so
// tests can assert an exact timestamp value.
func BuildPayload(serviceName string, counters Counters, now time.Time) ([]byte, error) {
	payload := Payload{
		Service:               serviceName,
		Timestamp:             now.UTC().Format(time.RFC3339),
		RequestCount:          counters.RequestCount,
		ErrorCount:            counters.ErrorCount,
		AverageResponseTimeMs: counters.AverageResponseTimeMs,
		ActiveConnections:     counters.ActiveConnections,
	}

	return json.Marshal(payload)
}
