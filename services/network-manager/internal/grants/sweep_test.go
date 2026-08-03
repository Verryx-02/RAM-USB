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
	mu         sync.Mutex
	expired    []Grant
	expiredErr error
	deleteErr  error
	// renewedHashes simulates a login that renewed the grant between
	// ExpiredGrants and DeleteGrant: the conditional delete finds no row
	// matching the expiry the sweep read, so it claims nothing.
	renewedHashes    map[string]bool
	deletedHashes    []string
	restored         []Grant
	restoreErr       error
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

func (f *fakeSweepStore) DeleteGrant(_ context.Context, emailHash string, _ time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return false, f.deleteErr
	}
	if f.renewedHashes[emailHash] {
		return false, nil
	}
	f.deletedHashes = append(f.deletedHashes, emailHash)
	return true, nil
}

func (f *fakeSweepStore) RestoreGrant(_ context.Context, g Grant) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restored = append(f.restored, g)
	return f.restoreErr
}

// deletedHashesSnapshot returns a copy of the claimed-row list so far,
// safe to call concurrently with ExpiredGrants/DeleteGrant.
func (f *fakeSweepStore) deletedHashesSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.deletedHashes))
	copy(out, f.deletedHashes)
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

	t.Run("claims and revokes every expired grant", func(t *testing.T) {
		store := &fakeSweepStore{expired: []Grant{
			{EmailHash: "hash-a", NodeID: 1, Tag: "tag:storage-access", ExpiresAt: now.Add(-time.Hour)},
			{EmailHash: "hash-b", NodeID: 2, Tag: "tag:storage-access", ExpiresAt: now.Add(-time.Minute)},
		}}
		revoker := &fakeRevoker{}

		if err := SweepOnce(context.Background(), store, revoker, now); err != nil {
			t.Fatalf("SweepOnce() error = %v", err)
		}
		if len(revoker.revoked) != 2 || revoker.revoked[0] != 1 || revoker.revoked[1] != 2 {
			t.Fatalf("revoked = %v, want [1 2]", revoker.revoked)
		}
		if len(store.deletedHashes) != 2 {
			t.Fatalf("deletedHashes = %v, want 2 entries", store.deletedHashes)
		}
		if len(store.restored) != 0 {
			t.Fatalf("restored = %v, want none (every revoke succeeded)", store.restored)
		}
	})

	t.Run("a grant renewed by a concurrent login is neither claimed nor revoked", func(t *testing.T) {
		// KI-36: the sweep read this grant as expired at T0, but a login
		// landing in the meantime re-applied the tag and wrote a fresh
		// expiry. Revoking now would silently strip access the user was
		// just told they had.
		store := &fakeSweepStore{
			expired: []Grant{
				{EmailHash: "hash-a", NodeID: 1, Tag: "tag:storage-access", ExpiresAt: now.Add(-time.Hour)},
				{EmailHash: "hash-b", NodeID: 2, Tag: "tag:storage-access", ExpiresAt: now.Add(-time.Minute)},
			},
			renewedHashes: map[string]bool{"hash-a": true},
		}
		revoker := &fakeRevoker{}

		if err := SweepOnce(context.Background(), store, revoker, now); err != nil {
			t.Fatalf("SweepOnce() error = %v", err)
		}
		if len(revoker.revoked) != 1 || revoker.revoked[0] != 2 {
			t.Fatalf("revoked = %v, want only [2] - node 1's grant was renewed", revoker.revoked)
		}
		if len(store.deletedHashes) != 1 || store.deletedHashes[0] != "hash-b" {
			t.Fatalf("deletedHashes = %v, want only [hash-b]", store.deletedHashes)
		}
	})

	t.Run("a revoke failure restores the claimed row for the next tick", func(t *testing.T) {
		store := &fakeSweepStore{expired: []Grant{
			{EmailHash: "hash-a", NodeID: 1, Tag: "tag:storage-access"},
			{EmailHash: "hash-b", NodeID: 2, Tag: "tag:storage-access"},
		}}
		revoker := &fakeRevoker{failFor: map[uint64]bool{1: true}}

		if err := SweepOnce(context.Background(), store, revoker, now); err != nil {
			t.Fatalf("SweepOnce() error = %v", err)
		}
		if len(revoker.revoked) != 2 {
			t.Fatalf("revoked = %v, want both attempted", revoker.revoked)
		}
		if len(store.restored) != 1 || store.restored[0].NodeID != 1 {
			t.Fatalf("restored = %+v, want node 1's row back for retry", store.restored)
		}
	})

	t.Run("a DeleteGrant failure skips that grant's revoke and does not abort the sweep", func(t *testing.T) {
		// The row could not be claimed, so its tag must stay applied:
		// revoking without a claim would reopen the race the claim
		// closes, and the row is still there to retry next tick.
		store := &fakeSweepStore{
			expired: []Grant{
				{EmailHash: "hash-a", NodeID: 1, Tag: "tag:storage-access"},
				{EmailHash: "hash-b", NodeID: 2, Tag: "tag:storage-access"},
			},
			deleteErr: errors.New("disk full"),
		}
		revoker := &fakeRevoker{}

		if err := SweepOnce(context.Background(), store, revoker, now); err != nil {
			t.Fatalf("SweepOnce() error = %v", err)
		}
		if len(revoker.revoked) != 0 {
			t.Fatalf("revoked = %v, want none (no row could be claimed)", revoker.revoked)
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
	store := &fakeSweepStore{expired: []Grant{{EmailHash: "hash-a", NodeID: 1, Tag: "tag:storage-access"}}}
	revoker := &fakeRevoker{}

	ctx, cancel := context.WithCancel(context.Background())
	go Run(ctx, 10*time.Millisecond, store, revoker)

	// Same real-short-interval wall-clock wait already established as
	// acceptable per Test_Plan §2.1 for "wait, then assert a call count
	// changed" (pkg/metrics's own schedule_test.go uses the identical
	// pattern for Run).
	deadline := time.Now().Add(500 * time.Millisecond)
	for len(store.deletedHashesSnapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	if store.expiredCalls() == 0 {
		t.Fatal("Run() never called ExpiredGrants")
	}
	if len(store.deletedHashesSnapshot()) == 0 {
		t.Fatal("Run() never swept the expired grant through to DeleteGrant")
	}
}
