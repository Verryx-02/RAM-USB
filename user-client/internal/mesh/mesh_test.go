package mesh

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Verryx-02/RAM-USB/user-client/internal/execrunner"
)

// Requirement: CL-F-04
func TestJoin_Success(t *testing.T) {
	fake := &execrunner.Fake{Output: []byte("Success.")}

	err := Join(context.Background(), fake, "https://headscale.example.com", "preauth-key-123")
	if err != nil {
		t.Fatalf("Join() error = %v, want nil", err)
	}

	want := [][]string{{"tailscale", "up", "--login-server=https://headscale.example.com", "--authkey=preauth-key-123"}}
	if !reflect.DeepEqual(fake.Calls, want) {
		t.Errorf("fake.Calls = %v, want %v", fake.Calls, want)
	}
}

// Requirement: CL-F-04
func TestJoin_CommandFailure_IsFlaggedNotSwallowed(t *testing.T) {
	fake := &execrunner.Fake{
		Output: []byte("tailscale: needs sudo"),
		Err:    errors.New("exit status 1"),
	}

	err := Join(context.Background(), fake, "https://headscale.example.com", "preauth-key-123")
	if !errors.Is(err, ErrJoinFailed) {
		t.Fatalf("Join() error = %v, want ErrJoinFailed", err)
	}
	if err.Error() == "" {
		t.Errorf("Join() error message is empty, want the command's output surfaced")
	}
}

// Requirement: CL-F-04
func TestJoin_RejectsEmptyArguments(t *testing.T) {
	tests := []struct {
		name        string
		loginServer string
		preauthKey  string
	}{
		{name: "empty login server", loginServer: "", preauthKey: "key"},
		{name: "empty preauth key", loginServer: "https://headscale.example.com", preauthKey: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &execrunner.Fake{}
			err := Join(context.Background(), fake, tt.loginServer, tt.preauthKey)
			if err == nil {
				t.Errorf("Join() error = nil, want non-nil")
			}
			if len(fake.Calls) != 0 {
				t.Errorf("Join() invoked tailscale despite invalid arguments: %v", fake.Calls)
			}
		})
	}
}
