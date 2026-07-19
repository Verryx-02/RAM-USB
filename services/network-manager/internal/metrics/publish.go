package metrics

import (
	"context"
	"errors"
	"fmt"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// publishQoS is MQTT "at least once" delivery - same reasoning as
// Database-Vault's own publish.go: a dropped metrics message is an
// acceptable loss (the next minute's publish supersedes it), but QoS 0
// risks silent loss for no benefit at a one-message-per-minute rate.
const publishQoS byte = 1

// publishTimeout bounds how long PublishOnce waits for the broker to
// acknowledge a single publish before giving up.
const publishTimeout = 10 * time.Second

// Publisher is the narrow subset of mqtt.Client's methods PublishOnce
// needs. A real *paho* mqtt.Client already satisfies this interface
// directly, no adapter type needed.
type Publisher interface {
	Publish(topic string, qos byte, retained bool, payload interface{}) mqtt.Token
	IsConnected() bool
}

// ErrPublisherNotConnected is returned when PublishOnce is asked to
// publish over a Publisher that is not currently connected to the
// broker (RD-04, fail-secure: never attempt a publish call that mqtt's
// client library would otherwise silently queue for a connection that
// may never be (re-)established).
var ErrPublisherNotConnected = errors.New("metrics: publisher is not connected to the broker")

// PublishOnce builds one aggregated metrics payload from counters and
// publishes it to Topic (NM-F-17), waiting up to publishTimeout for the
// broker's acknowledgement. It does not retry; the caller's scheduling
// loop (Run) decides whether and when to try again on the next interval.
func PublishOnce(ctx context.Context, publisher Publisher, counters Counters) error {
	if !publisher.IsConnected() {
		return ErrPublisherNotConnected
	}

	payload, err := BuildPayload(counters, time.Now())
	if err != nil {
		return fmt.Errorf("metrics: build payload: %w", err)
	}

	token := publisher.Publish(Topic, publishQoS, false, payload)

	select {
	case <-token.Done():
	case <-time.After(publishTimeout):
		return fmt.Errorf("metrics: publish to %s timed out after %s", Topic, publishTimeout)
	case <-ctx.Done():
		return ctx.Err()
	}

	if err := token.Error(); err != nil {
		return fmt.Errorf("metrics: publish to %s: %w", Topic, err)
	}

	return nil
}
