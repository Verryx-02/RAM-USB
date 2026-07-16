package metrics_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/metrics"
)

// fakeToken is a hand-written fake implementing mqtt.Token, already
// completed (Done channel closed) with a fixed error, per
// CONTRIBUTING.md 7.5's driver/stub pattern.
type fakeToken struct {
	done chan struct{}
	err  error
}

func newFakeToken(err error) *fakeToken {
	tok := &fakeToken{done: make(chan struct{}), err: err}
	close(tok.done)
	return tok
}

func (t *fakeToken) Wait() bool                     { return true }
func (t *fakeToken) WaitTimeout(time.Duration) bool { return true }
func (t *fakeToken) Done() <-chan struct{}          { return t.done }
func (t *fakeToken) Error() error                   { return t.err }

// fakePublisher is a hand-written fake implementing metrics.Publisher,
// recording every Publish call for assertion.
type fakePublisher struct {
	connected bool
	tokenErr  error
	calls     []publishCall
}

type publishCall struct {
	topic    string
	qos      byte
	retained bool
	payload  interface{}
}

func (p *fakePublisher) IsConnected() bool { return p.connected }

func (p *fakePublisher) Publish(topic string, qos byte, retained bool, payload interface{}) mqtt.Token {
	p.calls = append(p.calls, publishCall{topic, qos, retained, payload})
	return newFakeToken(p.tokenErr)
}

// Requirement: DV-F-16
func TestPublishOnce_PublishesToDedicatedTopic(t *testing.T) {
	publisher := &fakePublisher{connected: true}
	counters := metrics.Counters{RequestCount: 5, ErrorCount: 1, AverageResponseTimeMs: 3.2, ActiveConnections: 2}

	if err := metrics.PublishOnce(context.Background(), publisher, counters); err != nil {
		t.Fatalf("PublishOnce() error = %v", err)
	}

	if len(publisher.calls) != 1 {
		t.Fatalf("Publish called %d times, want exactly 1", len(publisher.calls))
	}

	call := publisher.calls[0]
	if call.topic != metrics.Topic {
		t.Errorf("Publish topic = %q, want %q", call.topic, metrics.Topic)
	}
	if call.retained {
		t.Errorf("Publish retained = true, want false (a stale retained metrics message must never be replayed to a new subscriber)")
	}

	payloadBytes, ok := call.payload.([]byte)
	if !ok {
		t.Fatalf("Publish payload type = %T, want []byte", call.payload)
	}

	var payload metrics.Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("json.Unmarshal(published payload) error = %v", err)
	}
	if payload.Service != metrics.ServiceName {
		t.Errorf("published payload.Service = %q, want %q", payload.Service, metrics.ServiceName)
	}
	if payload.RequestCount != counters.RequestCount {
		t.Errorf("published payload.RequestCount = %d, want %d", payload.RequestCount, counters.RequestCount)
	}
}

// Requirement: DV-F-16
func TestPublishOnce_NotConnected(t *testing.T) {
	publisher := &fakePublisher{connected: false}

	err := metrics.PublishOnce(context.Background(), publisher, metrics.Counters{})
	if !errors.Is(err, metrics.ErrPublisherNotConnected) {
		t.Fatalf("PublishOnce() error = %v, want ErrPublisherNotConnected", err)
	}
	if len(publisher.calls) != 0 {
		t.Fatalf("Publish called %d times, want 0 when not connected (fail-secure, RD-04)", len(publisher.calls))
	}
}

// Requirement: DV-F-16
func TestPublishOnce_BrokerRejectsPublish(t *testing.T) {
	wantErr := errors.New("broker rejected publish")
	publisher := &fakePublisher{connected: true, tokenErr: wantErr}

	err := metrics.PublishOnce(context.Background(), publisher, metrics.Counters{})
	if err == nil {
		t.Fatal("PublishOnce() error = nil, want the broker's rejection surfaced")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("PublishOnce() error = %v, want it to wrap %v", err, wantErr)
	}
}

// Requirement: DV-F-16
func TestPublishOnce_ContextCanceled(t *testing.T) {
	// A publisher whose token never completes, paired with an
	// already-canceled context, must make PublishOnce return promptly
	// via ctx.Done() rather than blocking for the full publishTimeout.
	publisher := &blockingPublisher{connected: true}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := metrics.PublishOnce(ctx, publisher, metrics.Counters{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PublishOnce() error = %v, want context.Canceled", err)
	}
}

// blockingPublisher returns a token that never completes, to exercise
// PublishOnce's ctx.Done() path without waiting out its real timeout.
type blockingPublisher struct {
	connected bool
}

func (p *blockingPublisher) IsConnected() bool { return p.connected }

func (p *blockingPublisher) Publish(string, byte, bool, interface{}) mqtt.Token {
	return &fakeToken{done: make(chan struct{})} // never closed
}
