// Package collector implements Metrics-Collector's MQTT message-handling
// logic: parsing the topic a message arrived on, independently validating
// that the payload's own "service" field agrees with it, and persisting
// only accepted payloads (MT-F-01, MT-F-02).
//
// MT-F-01 ("Metrics-Collector can only read metrics/*") is primarily
// enforced by third-party/mosquitto/acl.conf ("user MetricsCollector /
// topic read metrics/#") — a client authenticated as MetricsCollector
// cannot even subscribe to any other topic, let alone receive messages on
// one. cmd/metrics-collector/main.go's own subscription additionally only
// ever asks for "metrics/#", so this package never sees a non-metrics
// topic in practice; ServiceFromTopic's own rejection of anything not
// shaped "metrics/<service>" is defense-in-depth, not this requirement's
// primary enforcement point.
//
// MT-F-02 ("must discard metrics whose service field does not match the
// topic they came from") IS this package's own, separately-necessary
// check: the ACL only restricts which topics an authenticated MQTT client
// may WRITE to, not what a message's JSON body claims about itself. A
// compromised or misbehaving publisher holding a legitimate
// "topic write metrics/Entry-Hub" grant could still publish a payload
// whose "service" field says "Database-Vault" — Handle catches exactly
// that case and discards (never stores) the message.
package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

// topicPrefix is the fixed prefix every metrics topic carries — the
// inverse of metrics.TopicFor's "metrics/" + serviceName derivation.
const topicPrefix = "metrics/"

// insertTimeout bounds how long OnMessage waits for Store.Insert to
// complete for a single accepted payload, the same shape as
// pkg/metrics.PublishOnce's own publishTimeout on the publish side.
const insertTimeout = 10 * time.Second

// Store is the minimal persistence dependency Handler needs. A real
// internal/store.Store already satisfies this interface directly.
type Store interface {
	Insert(ctx context.Context, payload metrics.Payload) error
}

// Handler adapts an MQTT message arriving on any "metrics/<service>"
// topic into a validated Store.Insert call.
type Handler struct {
	Store Store
}

// ServiceFromTopic derives the metrics.Payload.Service value a message on
// topic is expected to carry — the inverse of metrics.TopicFor(service).
// ok is false if topic is not shaped "metrics/<non-empty-service>" at
// all.
func ServiceFromTopic(topic string) (service string, ok bool) {
	rest, hasPrefix := strings.CutPrefix(topic, topicPrefix)
	if !hasPrefix || rest == "" {
		return "", false
	}
	return rest, true
}

// Handle parses rawPayload as a metrics.Payload and inserts it via Store,
// after checking (MT-F-02) that the payload's own "service" field matches
// the topic it actually arrived on. A topic that doesn't match
// "metrics/<service>", a payload that fails to decode, or a service-field
// mismatch are all discarded — not stored — and logged; Handle returns a
// non-nil error only for a genuine Store failure, never for a discard,
// since a discard is Handle correctly doing its job (RD-04, fail-secure:
// an untrustworthy payload is dropped, not stored under a best guess).
func (h *Handler) Handle(ctx context.Context, topic string, rawPayload []byte) error {
	expectedService, ok := ServiceFromTopic(topic)
	if !ok {
		slog.Warn("metrics-collector: discarding message on unrecognized topic",
			"topic", logging.Sanitize(topic))
		return nil
	}

	decoder := json.NewDecoder(bytes.NewReader(rawPayload))
	decoder.DisallowUnknownFields()
	var payload metrics.Payload
	if err := decoder.Decode(&payload); err != nil {
		slog.Warn("metrics-collector: discarding message with unparseable payload",
			"topic", logging.Sanitize(topic), "error", logging.Sanitize(err.Error()))
		return nil
	}

	if payload.Service != expectedService {
		slog.Warn("metrics-collector: discarding message whose payload service does not match its topic",
			"topic", logging.Sanitize(topic), "payload_service", logging.Sanitize(payload.Service))
		return nil
	}

	if err := h.Store.Insert(ctx, payload); err != nil {
		return fmt.Errorf("collector: insert metrics payload: %w", err)
	}

	return nil
}

// OnMessage adapts Handle to paho's mqtt.MessageHandler signature (a
// fixed (mqtt.Client, mqtt.Message) callback with no context parameter of
// its own), the value passed to mqtt.Client.Subscribe in
// cmd/metrics-collector/main.go. Any error Handle returns (a genuine
// Store failure, not a discard — see Handle's own doc comment) is logged
// here, since MessageHandler's signature has no way to propagate it to a
// caller.
func (h *Handler) OnMessage(_ mqtt.Client, msg mqtt.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), insertTimeout)
	defer cancel()

	if err := h.Handle(ctx, msg.Topic(), msg.Payload()); err != nil {
		slog.Error("metrics-collector: handle message failed",
			"topic", logging.Sanitize(msg.Topic()), "error", logging.Sanitize(err.Error()))
	}
}
