package grants

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeSweepStore is a hand-written fake implementing SweepStore
// (CONTRIBUTING.md §7.5). Its fields are guarded by mu because
// TestRun_TicksAndSweeps drives it from Run's background goroutine while
// polling/asserting from the test's own goroutine concurrently; every
// access (including the test's own reads) must go through the accessor
// methods below, never the raw fields directly.
type fakeSweepStore struct {
	mu               sync.Mutex
	expired          []Grant
	expiredErr       error
	deleteErr        error
	deletedEmails    []string
	expiredCallCount int
}

func (f *fakeSweepStore) ExpiredGrants(_ context.Context, _ time.Time) ([]Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expiredCallCount++
	if f.expiredErr != nil {
		return nil, f.expiredErr
	}
	return f.expired, nil
}

func (f *fakeSweepStore) DeleteGrant(_ context.Context, email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletedEmails = append(f.deletedEmails, email)
	return f.deleteErr
}

// deletedEmailsSnapshot returns a copy of the deleted-email list so far,
// safe to call concurrently with ExpiredGrants/DeleteGrant.
func (f *fakeSweepStore) deletedEmailsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.deletedEmails))
	copy(out, f.deletedEmails)
	return out
}

// expiredCalls returns the current ExpiredGrants call count, safe to call
// concurrently with ExpiredGrants/DeleteGrant.
func (f *fakeSweepStore) expiredCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.expiredCallCount
}

// fakeRevoker is a hand-written fake implementing Revoker.
type fakeRevoker struct {
	err        error
	failFor    map[uint64]bool
	revoked    []uint64
	revokedTag []string
}

func (f *fakeRevoker) Revoke(_ context.Context, nodeID uint64, tag string) error {
	f.revoked = append(f.revoked, nodeID)
	f.revokedTag = append(f.revokedTag, tag)
	if f.failFor != nil && f.failFor[nodeID] {
		return errors.New("revoke failed")
	}
	return f.err
}

// Requirement: NM-F-10
func TestSweepOnce(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	t.Run("revokes and deletes every expired grant", func(t *testing.T) {
		store := &fakeSweepStore{expired: []Grant{
			{Email: "a@example.com", NodeID: 1, Tag: "tag:storage-access", ExpiresAt: now.Add(-time.Hour)},
			{Email: "b@example.com", NodeID: 2, Tag: "tag:storage-access", ExpiresAt: now.Add(-time.Minute)},
		}}
		revoker := &fakeRevoker{}

		if err := SweepOnce(context.Background(), store, revoker, now); err != nil {
			t.Fatalf("SweepOnce() error = %v", err)
		}
		if len(revoker.revoked) != 2 || revoker.revoked[0] != 1 || revoker.revoked[1] != 2 {
			t.Fatalf("revoked = %v, want [1 2]", revoker.revoked)
		}
		if len(store.deletedEmails) != 2 {
			t.Fatalf("deletedEmails = %v, want 2 entries", store.deletedEmails)
		}
	})

	t.Run("a revoke failure for one grant does not stop the sweep, and its row is kept for retry", func(t *testing.T) {
		store := &fakeSweepStore{expired: []Grant{
			{Email: "a@example.com", NodeID: 1, Tag: "tag:storage-access"},
			{Email: "b@example.com", NodeID: 2, Tag: "tag:storage-access"},
		}}
		revoker := &fakeRevoker{failFor: map[uint64]bool{1: true}}

		if err := SweepOnce(context.Background(), store, revoker, now); err != nil {
			t.Fatalf("SweepOnce() error = %v", err)
		}
		if len(revoker.revoked) != 2 {
			t.Fatalf("revoked = %v, want both attempted", revoker.revoked)
		}
		if len(store.deletedEmails) != 1 || store.deletedEmails[0] != "b@example.com" {
			t.Fatalf("deletedEmails = %v, want only [b@example.com] (a's row must survive for retry)", store.deletedEmails)
		}
	})

	t.Run("a DeleteGrant failure does not abort the rest of the sweep", func(t *testing.T) {
		store := &fakeSweepStore{
			expired: []Grant{
				{Email: "a@example.com", NodeID: 1, Tag: "tag:storage-access"},
				{Email: "b@example.com", NodeID: 2, Tag: "tag:storage-access"},
			},
			deleteErr: errors.New("disk full"),
		}
		revoker := &fakeRevoker{}

		if err := SweepOnce(context.Background(), store, revoker, now); err != nil {
			t.Fatalf("SweepOnce() error = %v", err)
		}
		if len(revoker.revoked) != 2 {
			t.Fatalf("revoked = %v, want both attempted despite delete failures", revoker.revoked)
		}
	})

	t.Run("ExpiredGrants failure surfaces as SweepOnce's own error", func(t *testing.T) {
		store := &fakeSweepStore{expiredErr: errors.New("boom")}
		revoker := &fakeRevoker{}

		err := SweepOnce(context.Background(), store, revoker, now)
		if err == nil {
			t.Fatal("SweepOnce() error = nil, want non-nil")
		}
		if len(revoker.revoked) != 0 {
			t.Fatal("Revoke was called despite ExpiredGrants failing")
		}
	})

	t.Run("nothing expired is a no-op, not an error", func(t *testing.T) {
		store := &fakeSweepStore{}
		revoker := &fakeRevoker{}

		if err := SweepOnce(context.Background(), store, revoker, now); err != nil {
			t.Fatalf("SweepOnce() error = %v", err)
		}
		if len(revoker.revoked) != 0 {
			t.Fatal("Revoke was called with nothing expired")
		}
	})
}

// Requirement: NM-F-10
func TestRun_TicksAndSweeps(t *testing.T) {
	store := &fakeSweepStore{expired: []Grant{{Email: "a@example.com", NodeID: 1, Tag: "tag:storage-access"}}}
	revoker := &fakeRevoker{}

	ctx, cancel := context.WithCancel(context.Background())
	go Run(ctx, 10*time.Millisecond, store, revoker)

	// Same real-short-interval wall-clock wait already established as
	// acceptable per Test_Plan §2.1 for "wait, then assert a call count
	// changed" (services/database-vault/internal/metrics.schedule_test.go
	// uses the identical pattern for DV-F-16's Run).
	deadline := time.Now().Add(500 * time.Millisecond)
	for len(store.deletedEmailsSnapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	if store.expiredCalls() == 0 {
		t.Fatal("Run() never called ExpiredGrants")
	}
	if len(store.deletedEmailsSnapshot()) == 0 {
		t.Fatal("Run() never swept the expired grant through to DeleteGrant")
	}
}
