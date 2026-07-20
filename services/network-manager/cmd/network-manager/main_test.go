package main

import (
	"context"
	"errors"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"

	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
)

// fakePolicyPusher is a hand-written fake of headscale.PolicyPusher
// (CONTRIBUTING.md §7.5), same shape as
// internal/headscale/policy_test.go's own fakePolicyPusher - kept as a
// separate, narrower copy here rather than exported/reused across
// packages, since this file only needs to prove pushStartupPolicy's own
// wiring (call SetPolicy exactly once, propagate any error), not
// PolicyDocument's exact byte content (already covered by
// internal/headscale/policy_test.go).
type fakePolicyPusher struct {
	setPolicyErr  error
	setPolicyCall int
}

func (f *fakePolicyPusher) SetPolicy(_ context.Context, in *v1.SetPolicyRequest, _ ...grpc.CallOption) (*v1.SetPolicyResponse, error) {
	f.setPolicyCall++
	if f.setPolicyErr != nil {
		return nil, f.setPolicyErr
	}
	return &v1.SetPolicyResponse{Policy: in.GetPolicy()}, nil
}

func (f *fakePolicyPusher) GetPolicy(_ context.Context, _ *v1.GetPolicyRequest, _ ...grpc.CallOption) (*v1.GetPolicyResponse, error) {
	return &v1.GetPolicyResponse{}, nil
}

// Requirement: NM-F-01
// Requirement: NM-F-02
// Requirement: NM-F-03
// Requirement: NM-F-04
// Requirement: NM-F-05
// Requirement: NM-F-06
// Requirement: NM-F-07
//
// pushStartupPolicy is the function run() calls, at startup, to apply
// Network-Manager's static ACL policy to Headscale (see run()'s own doc
// comment on the call site for why a PushPolicy failure is fatal, not a
// degrade-with-warning). This proves both directions of that wiring: a
// successful push calls SetPolicy exactly once and returns nil, and a
// failed push propagates the underlying error rather than swallowing it -
// which is what makes run()'s own fmt.Errorf-and-abort behavior at the
// call site meaningful.
func TestPushStartupPolicy(t *testing.T) {
	t.Run("success calls SetPolicy exactly once and returns nil", func(t *testing.T) {
		fake := &fakePolicyPusher{}

		if err := pushStartupPolicy(context.Background(), fake); err != nil {
			t.Fatalf("pushStartupPolicy() error = %v, want nil", err)
		}
		if fake.setPolicyCall != 1 {
			t.Fatalf("SetPolicy called %d times, want 1", fake.setPolicyCall)
		}
	})

	t.Run("SetPolicy failure is propagated, not swallowed", func(t *testing.T) {
		fake := &fakePolicyPusher{setPolicyErr: errors.New("headscale: connection refused")}

		err := pushStartupPolicy(context.Background(), fake)
		if err == nil {
			t.Fatal("pushStartupPolicy() error = nil, want non-nil")
		}
		// PushPolicy (internal/headscale/policy.go) wraps every SetPolicy
		// failure in ErrHeadscaleRequestFailed, not the fake's own
		// underlying error value directly (fmt.Errorf's "%w: ...: %v",
		// same pattern as every other headscale client call - see
		// policy_test.go's identical assertion), which is what run()'s own
		// fmt.Errorf("push headscale acl policy ...: %w", err) call site
		// then wraps a second time.
		if !errors.Is(err, headscale.ErrHeadscaleRequestFailed) {
			t.Fatalf("pushStartupPolicy() error = %v, want wrapping headscale.ErrHeadscaleRequestFailed", err)
		}
	})
}
