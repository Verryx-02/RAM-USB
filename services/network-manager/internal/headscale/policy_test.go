package headscale_test

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"

	hs "github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
)

// decodedPolicy mirrors just enough of the pushed JSON's shape to assert
// on it - a second, independent decoding of the same wire format
// policy.go's own policyDocument/policyACL types produce, so the test
// isn't merely re-checking the production struct's own field tags against
// itself.
type decodedPolicy struct {
	Groups    map[string][]string `json:"groups"`
	TagOwners map[string][]string `json:"tagOwners"`
	ACLs      []decodedACL        `json:"acls"`
}

type decodedACL struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// findRule returns the single ACL rule whose Dst set exactly equals want,
// failing the test if there isn't exactly one such rule. Rules in this
// policy are uniquely identified by their destination set (no two rules
// share one), which is a more robust match than asserting a fixed slice
// index.
func findRule(t *testing.T, acls []decodedACL, dst ...string) decodedACL {
	t.Helper()
	want := sorted(dst)

	var matches []decodedACL
	for _, acl := range acls {
		if got := sorted(acl.Dst); equalStrings(got, want) {
			matches = append(matches, acl)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("findRule(dst=%v): found %d matching rules, want exactly 1 (acls=%+v)", dst, len(matches), acls)
	}
	return matches[0]
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Requirement: NM-F-01, NM-F-02, NM-F-03, NM-F-04, NM-F-05, NM-F-06, NM-F-07
//
// Asserts PolicyDocument's generated JSON contains exactly the right
// src/dst pairs for every rule this task's six requirements (plus the
// NM-F-03 rule buildACLs' own doc comment explains including) translate
// to - no more, no less - cross-checked against
// docs/design/diagrams/09-security-trust-zones.puml's arrows, not
// re-derived from the SRS prose alone.
func TestPolicyDocument_Content(t *testing.T) {
	data, err := hs.PolicyDocument()
	if err != nil {
		t.Fatalf("PolicyDocument() error = %v", err)
	}

	var doc decodedPolicy
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("json.Unmarshal(PolicyDocument()) error = %v", err)
	}

	if len(doc.ACLs) != 7 {
		t.Fatalf("len(doc.ACLs) = %d, want 7 (NM-F-01, 02, 03, 04x2, 05, 06/07)", len(doc.ACLs))
	}

	for i, acl := range doc.ACLs {
		if acl.Action != "accept" {
			t.Errorf("doc.ACLs[%d].Action = %q, want %q", i, acl.Action, "accept")
		}
	}

	tests := []struct {
		name    string
		dst     []string
		wantSrc []string
	}{
		{
			name:    "NM-F-01: only Entry-Hub, Database-Vault, Network-Manager, Certificate-Authority can contact Security-Switch",
			dst:     []string{hs.TagSecuritySwitch + ":*"},
			wantSrc: []string{hs.TagEntryHub, hs.TagDatabaseVault, hs.TagNetworkManager, hs.TagCertificateAuthority},
		},
		{
			name:    "NM-F-02: only Security-Switch, Storage-Service, Certificate-Authority can contact Database-Vault",
			dst:     []string{hs.TagDatabaseVault + ":*"},
			wantSrc: []string{hs.TagSecuritySwitch, hs.TagStorageService, hs.TagCertificateAuthority},
		},
		{
			name:    "NM-F-03: only Security-Switch, Certificate-Authority can contact Network-Manager",
			dst:     []string{hs.TagNetworkManager + ":*"},
			wantSrc: []string{hs.TagSecuritySwitch, hs.TagCertificateAuthority},
		},
		{
			name:    "NM-F-04 direction one: every internal component can contact Certificate-Authority",
			dst:     []string{hs.TagCertificateAuthority + ":*"},
			wantSrc: []string{hs.TagEntryHub, hs.TagSecuritySwitch, hs.TagDatabaseVault, hs.TagStorageService, hs.TagNetworkManager},
		},
		{
			name: "NM-F-04 direction two: Certificate-Authority can contact every internal component",
			dst: []string{
				hs.TagEntryHub + ":*",
				hs.TagSecuritySwitch + ":*",
				hs.TagDatabaseVault + ":*",
				hs.TagStorageService + ":*",
				hs.TagNetworkManager + ":*",
			},
			wantSrc: []string{hs.TagCertificateAuthority},
		},
		{
			name:    "NM-F-05/NM-F-07 (authenticated half): only TagStorageAccess nodes can contact Storage-Service",
			dst:     []string{hs.TagStorageService + ":*"},
			wantSrc: []string{hs.TagStorageAccess},
		},
		{
			name:    "NM-F-06/NM-F-07 (registered half): every TagMeshMember node can contact Entry-Hub",
			dst:     []string{hs.TagEntryHub + ":*"},
			wantSrc: []string{hs.TagMeshMember},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := findRule(t, doc.ACLs, tc.dst...)
			gotSrc, wantSrc := sorted(rule.Src), sorted(tc.wantSrc)
			if !equalStrings(gotSrc, wantSrc) {
				t.Errorf("rule with dst=%v: Src = %v, want %v", tc.dst, gotSrc, wantSrc)
			}
		})
	}
}

// Requirement: NM-F-01, NM-F-02, NM-F-03, NM-F-04, NM-F-05, NM-F-06, NM-F-07
//
// Every tag referenced by any ACL's src/dst must also be declared in
// tagOwners, or Headscale's own SetPolicy rejects the whole document
// (confirmed empirically this session against a real Headscale container
// via "headscale policy check", see policy.go's package doc comment) -
// this test catches a future rule referencing a tag this file forgot to
// add to tagOwners, independent of whether a live Headscale server is
// available.
func TestPolicyDocument_EveryReferencedTagHasAnOwner(t *testing.T) {
	data, err := hs.PolicyDocument()
	if err != nil {
		t.Fatalf("PolicyDocument() error = %v", err)
	}

	var doc decodedPolicy
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("json.Unmarshal(PolicyDocument()) error = %v", err)
	}

	referenced := map[string]bool{}
	for _, acl := range doc.ACLs {
		for _, s := range acl.Src {
			referenced[s] = true
		}
		for _, d := range acl.Dst {
			// Strip the ":*" port suffix findRule/buildACLs add - tagOwners
			// keys are bare tags, never alias:port strings.
			tag := d
			if idx := len(d) - len(":*"); idx > 0 && d[idx:] == ":*" {
				tag = d[:idx]
			}
			referenced[tag] = true
		}
	}

	for tag := range referenced {
		if _, ok := doc.TagOwners[tag]; !ok {
			t.Errorf("tag %q is referenced by an ACL rule but has no tagOwners entry", tag)
		}
	}
}

// fakePolicyPusher is a hand-written fake of hs.PolicyPusher (CONTRIBUTING.md
// §7.5) - no real Headscale connection is needed to exercise PushPolicy's
// own wiring (construct the request, call SetPolicy, wrap a failure).
type fakePolicyPusher struct {
	setPolicyErr  error
	gotPolicy     string
	setPolicyCall int
}

func (f *fakePolicyPusher) SetPolicy(_ context.Context, in *v1.SetPolicyRequest, _ ...grpc.CallOption) (*v1.SetPolicyResponse, error) {
	f.setPolicyCall++
	f.gotPolicy = in.GetPolicy()
	if f.setPolicyErr != nil {
		return nil, f.setPolicyErr
	}
	return &v1.SetPolicyResponse{Policy: in.GetPolicy()}, nil
}

func (f *fakePolicyPusher) GetPolicy(_ context.Context, _ *v1.GetPolicyRequest, _ ...grpc.CallOption) (*v1.GetPolicyResponse, error) {
	return &v1.GetPolicyResponse{Policy: f.gotPolicy}, nil
}

// Requirement: NM-F-01, NM-F-02, NM-F-04, NM-F-05, NM-F-06, NM-F-07
func TestPushPolicy(t *testing.T) {
	t.Run("success pushes the exact PolicyDocument bytes", func(t *testing.T) {
		fake := &fakePolicyPusher{}
		if err := hs.PushPolicy(context.Background(), fake); err != nil {
			t.Fatalf("PushPolicy() error = %v", err)
		}
		if fake.setPolicyCall != 1 {
			t.Fatalf("SetPolicy called %d times, want 1", fake.setPolicyCall)
		}

		want, err := hs.PolicyDocument()
		if err != nil {
			t.Fatalf("PolicyDocument() error = %v", err)
		}
		if fake.gotPolicy != string(want) {
			t.Errorf("SetPolicy received %q, want %q", fake.gotPolicy, string(want))
		}
	})

	t.Run("SetPolicy failure is wrapped in ErrHeadscaleRequestFailed", func(t *testing.T) {
		wantErr := errors.New("boom")
		fake := &fakePolicyPusher{setPolicyErr: wantErr}

		err := hs.PushPolicy(context.Background(), fake)
		if !errors.Is(err, hs.ErrHeadscaleRequestFailed) {
			t.Fatalf("PushPolicy() error = %v, want wrapping ErrHeadscaleRequestFailed", err)
		}
	})
}
