package grants

import (
	"context"
	"log/slog"
	"time"
)

// SweepStore is the narrow interface Sweep needs against Store: find every
// expired grant, then remove its persisted row once revoked. A real
// *Store already satisfies this directly (structural typing, no adapter
// type - same shape as httpapi.GrantRecorder over Store's RecordGrant).
type SweepStore interface {
	ExpiredGrants(ctx context.Context, now time.Time) ([]Grant, error)
	DeleteGrant(ctx context.Context, email string) error
}

// Revoker performs the real Headscale tag removal for one expired grant.
// A production caller binds this to internal/headscale.RevokeStorageAccess
// (or, for a tag other than TagStorageAccess, RemoveNodeTag) - see
// cmd/network-manager/main.go's wiring for the concrete adapter, kept
// there rather than in this package so internal/grants stays free of a
// dependency on internal/headscale's Headscale-specific types (per
// CONTRIBUTING.md §7.2's package-layout guidance: cmd/<service>/main.go
// owns dependency construction/wiring).
type Revoker interface {
	Revoke(ctx context.Context, nodeID uint64, tag string) error
}

// SweepOnce implements NM-F-10's one-tick logic: find every grant whose
// expiry has passed, revoke the corresponding ACL tag via revoker, and
// delete the persisted row once the revoke succeeds. A revoke failure for
// one grant is logged and does not stop the sweep from processing the
// rest - same "one failure does not end the loop" reasoning as
// metrics.Run's publish-failure handling - and deliberately does NOT
// delete that grant's row, so the next tick retries it rather than
// silently forgetting an ACL tag still needs removing (RD-04,
// fail-secure: losing track of an overdue revoke is worse than retrying
// one that already succeeded server-side but whose row deletion itself
// then failed - see the second failure branch below for that narrower
// case).
func SweepOnce(ctx context.Context, store SweepStore, revoker Revoker, now time.Time) error {
	expired, err := store.ExpiredGrants(ctx, now)
	if err != nil {
		return err
	}

	for _, grant := range expired {
		if err := revoker.Revoke(ctx, grant.NodeID, grant.Tag); err != nil {
			slog.Error("grants: sweep failed to revoke expired grant, will retry next tick",
				"node_id", grant.NodeID, "tag", grant.Tag, "error", err)
			continue
		}
		if err := store.DeleteGrant(ctx, grant.Email); err != nil {
			// The tag is already removed server-side at this point; a
			// leftover row only causes a harmless repeat revoke attempt
			// next tick (internal/headscale.RemoveNodeTag/RevokeStorageAccess
			// removing an already-absent tag is a no-op via removeTag),
			// not a security issue - logged, not escalated to abort the
			// rest of this sweep tick.
			slog.Error("grants: sweep revoked a grant but failed to delete its persisted row, will retry next tick",
				"node_id", grant.NodeID, "tag", grant.Tag, "error", err)
		}
	}

	return nil
}

// Run calls SweepOnce once per interval tick, until ctx is canceled
// (NM-F-10: "periodically ... automatically and without manual
// intervention"). Same ticker shape as
// services/database-vault/internal/metrics.Run: tick then sweep, no
// immediate sweep on start, a failed tick is logged and does not stop the
// loop.
func Run(ctx context.Context, interval time.Duration, store SweepStore, revoker Revoker) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := SweepOnce(ctx, store, revoker, time.Now()); err != nil {
				slog.Error("grants: sweep cycle failed", "error", err)
			}
		}
	}
}
