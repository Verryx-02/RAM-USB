package grants

import (
	"context"
	"log/slog"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
)

// SweepStore is the narrow interface Sweep needs against Store: find every
// expired grant, claim its row (a delete conditioned on the expiry that
// was read, so a concurrent renewal wins), and put a claimed row back if
// the revoke that followed failed. A real *Store already satisfies this
// directly (structural typing, no adapter type - same shape as
// httpapi.GrantRecorder over Store's RecordGrant).
type SweepStore interface {
	ExpiredGrants(ctx context.Context, now time.Time) ([]Grant, error)
	DeleteGrant(ctx context.Context, emailHash string, expiresAt time.Time) (bool, error)
	RestoreGrant(ctx context.Context, g Grant) error
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
// expiry has passed, claim its persisted row, and revoke the corresponding
// ACL tag.
//
// The row is claimed BEFORE the revoke, with a delete conditioned on the
// exact expiry read at the start of this tick. A revoke is a network round
// trip, and a login landing inside that window re-applies the tag and
// writes a fresh expiry (httpapi.Handler.Grant, NM-F-09): an unconditional
// delete-after-revoke would strip the tag the user was just told they had
// and remove the new row with it, leaving nothing behind to notice. With
// the conditional delete, a renewal simply makes the claim fail (zero rows
// affected) and this tick skips that grant entirely - the fresh grant is
// left alone and expires on its own schedule.
//
// If the revoke then fails, the claimed row is put back (RestoreGrant) so
// the next tick retries rather than forgetting an ACL tag that is still
// applied (RD-04, fail-secure). A failure of any single grant is logged
// and does not stop the rest of the tick - same "one failure does not end
// the loop" reasoning as metrics.Run's publish-failure handling.
func SweepOnce(ctx context.Context, store SweepStore, revoker Revoker, now time.Time) error {
	expired, err := store.ExpiredGrants(ctx, now)
	if err != nil {
		return err
	}

	for _, grant := range expired {
		claimed, err := store.DeleteGrant(ctx, grant.EmailHash, grant.ExpiresAt)
		if err != nil {
			slog.Error("grants: sweep failed to claim expired grant's row, will retry next tick",
				"node_id", grant.NodeID, "tag", grant.Tag, "error", logging.Sanitize(err.Error()))
			continue
		}
		if !claimed {
			// A concurrent login renewed (or already swept) this grant
			// between ExpiredGrants and here - its tag belongs to the new
			// grant, so it must not be revoked now.
			continue
		}

		if err := revoker.Revoke(ctx, grant.NodeID, grant.Tag); err != nil {
			slog.Error("grants: sweep failed to revoke expired grant, restoring its row for the next tick",
				"node_id", grant.NodeID, "tag", grant.Tag, "error", logging.Sanitize(err.Error()))
			if restoreErr := store.RestoreGrant(ctx, grant); restoreErr != nil {
				// Nothing is left on disk to drive a retry: the tag stays
				// applied until an operator removes it. Logged at Error
				// for exactly that reason.
				slog.Error("grants: sweep could not restore an unrevoked grant's row, its ACL tag now needs manual removal",
					"node_id", grant.NodeID, "tag", grant.Tag, "error", logging.Sanitize(restoreErr.Error()))
			}
		}
	}

	return nil
}

// Run calls SweepOnce once per interval tick, until ctx is canceled
// (NM-F-10: "periodically ... automatically and without manual
// intervention"). Same ticker shape as pkg/metrics.Run: tick then sweep,
// no immediate sweep on start, a failed tick is logged and does not stop
// the loop.
func Run(ctx context.Context, interval time.Duration, store SweepStore, revoker Revoker) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := SweepOnce(ctx, store, revoker, time.Now()); err != nil {
				slog.Error("grants: sweep cycle failed", "error", logging.Sanitize(err.Error()))
			}
		}
	}
}
