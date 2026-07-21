package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

// fakeStore is a hand-written fake of Store (CONTRIBUTING.md §7.5).
type fakeStore struct {
	insertErr   error
	insertCalls int
	lastPayload metrics.Payload
}

func (f *fakeStore) Insert(_ context.Context, payload metrics.Payload) error {
	f.insertCalls++
	f.lastPayload = payload
	return f.insertErr
}

// Requirement: MT-F-01
func TestServiceFromTopic(t *testing.T) {
	tests := []struct {
		name        string
		topic       string
		wantService string
		wantOK      bool
	}{
		{name: "well-formed metrics topic", topic: "metrics/Entry-Hub", wantService: "Entry-Hub", wantOK: true},
		{name: "well-formed metrics topic, different service", topic: "metrics/Database-Vault", wantService: "Database-Vault", wantOK: true},
		{name: "bare metrics prefix with no service", topic: "metrics/", wantService: "", wantOK: false},
		{name: "no metrics prefix at all", topic: "other/Entry-Hub", wantService: "", wantOK: false},
		{name: "empty topic", topic: "", wantService: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotService, gotOK := ServiceFromTopic(tt.topic)
			if gotOK != tt.wantOK || gotService != tt.wantService {
				t.Fatalf("ServiceFromTopic(%q) = (%q, %v), want (%q, %v)",
					tt.topic, gotService, gotOK, tt.wantService, tt.wantOK)
			}
		})
	}
}

// Requirement: MT-F-02
func TestHandler_Handle(t *testing.T) {
	validPayload := `{"service":"Entry-Hub","timestamp":"2026-07-21T12:00:00Z","request_count":10,"error_count":0,"average_response_time_ms":5.5,"active_connections":2}`

	t.Run("matching topic and payload service is inserted", func(t *testing.T) {
		fake := &fakeStore{}
		h := &Handler{Store: fake}

		if err := h.Handle(context.Background(), "metrics/Entry-Hub", []byte(validPayload)); err != nil {
			t.Fatalf("Handle() error = %v, want nil", err)
		}
		if fake.insertCalls != 1 {
			t.Fatalf("Insert called %d times, want 1", fake.insertCalls)
		}
		if fake.lastPayload.Service != "Entry-Hub" {
			t.Fatalf("inserted payload service = %q, want %q", fake.lastPayload.Service, "Entry-Hub")
		}
	})

	t.Run("payload service mismatching its topic is discarded, not inserted", func(t *testing.T) {
		fake := &fakeStore{}
		h := &Handler{Store: fake}

		// The ACL only restricts which topic a client may WRITE to
		// (third-party/mosquitto/acl.conf) - it does not stop a payload's
		// own "service" JSON field from lying about which service it
		// actually came from. This is the MT-F-02 case this package
		// exists to catch.
		mismatched := `{"service":"Database-Vault","timestamp":"2026-07-21T12:00:00Z","request_count":10,"error_count":0,"average_response_time_ms":5.5,"active_connections":2}`

		if err := h.Handle(context.Background(), "metrics/Entry-Hub", []byte(mismatched)); err != nil {
			t.Fatalf("Handle() error = %v, want nil (a discard is not an error)", err)
		}
		if fake.insertCalls != 0 {
			t.Fatalf("Insert called %d times, want 0 (mismatched payload must be discarded)", fake.insertCalls)
		}
	})

	t.Run("unrecognized topic is discarded, not inserted", func(t *testing.T) {
		fake := &fakeStore{}
		h := &Handler{Store: fake}

		if err := h.Handle(context.Background(), "other/Entry-Hub", []byte(validPayload)); err != nil {
			t.Fatalf("Handle() error = %v, want nil", err)
		}
		if fake.insertCalls != 0 {
			t.Fatalf("Insert called %d times, want 0", fake.insertCalls)
		}
	})

	t.Run("unparseable payload is discarded, not inserted", func(t *testing.T) {
		fake := &fakeStore{}
		h := &Handler{Store: fake}

		if err := h.Handle(context.Background(), "metrics/Entry-Hub", []byte("{not json")); err != nil {
			t.Fatalf("Handle() error = %v, want nil", err)
		}
		if fake.insertCalls != 0 {
			t.Fatalf("Insert called %d times, want 0", fake.insertCalls)
		}
	})

	t.Run("payload with an unknown field is discarded, not inserted", func(t *testing.T) {
		fake := &fakeStore{}
		h := &Handler{Store: fake}

		withExtraField := `{"service":"Entry-Hub","timestamp":"2026-07-21T12:00:00Z","request_count":10,"error_count":0,"average_response_time_ms":5.5,"active_connections":2,"email":"user@example.com"}`

		if err := h.Handle(context.Background(), "metrics/Entry-Hub", []byte(withExtraField)); err != nil {
			t.Fatalf("Handle() error = %v, want nil", err)
		}
		if fake.insertCalls != 0 {
			t.Fatalf("Insert called %d times, want 0", fake.insertCalls)
		}
	})

	t.Run("Store failure is propagated", func(t *testing.T) {
		wantErr := errors.New("connection refused")
		fake := &fakeStore{insertErr: wantErr}
		h := &Handler{Store: fake}

		err := h.Handle(context.Background(), "metrics/Entry-Hub", []byte(validPayload))
		if !errors.Is(err, wantErr) {
			t.Fatalf("Handle() error = %v, want wrapping %v", err, wantErr)
		}
	})
}

// Requirement: MT-F-02
func TestHandler_OnMessage(t *testing.T) {
	validPayload := `{"service":"Entry-Hub","timestamp":"2026-07-21T12:00:00Z","request_count":10,"error_count":0,"average_response_time_ms":5.5,"active_connections":2}`

	t.Run("delegates to Handle via the fixed MessageHandler signature", func(t *testing.T) {
		fake := &fakeStore{}
		h := &Handler{Store: fake}

		h.OnMessage(nil, fakeMessage{topic: "metrics/Entry-Hub", payload: []byte(validPayload)})

		if fake.insertCalls != 1 {
			t.Fatalf("Insert called %d times, want 1", fake.insertCalls)
		}
	})
}

// fakeMessage is a hand-written fake of mqtt.Message (CONTRIBUTING.md
// §7.5) — only Topic() and Payload() are exercised by OnMessage/Handle,
// every other method is an unused stub.
type fakeMessage struct {
	topic   string
	payload []byte
}

func (f fakeMessage) Duplicate() bool   { return false }
func (f fakeMessage) Qos() byte         { return 1 }
func (f fakeMessage) Retained() bool    { return false }
func (f fakeMessage) Topic() string     { return f.topic }
func (f fakeMessage) MessageID() uint16 { return 0 }
func (f fakeMessage) Payload() []byte   { return f.payload }
func (f fakeMessage) Ack()              {}
