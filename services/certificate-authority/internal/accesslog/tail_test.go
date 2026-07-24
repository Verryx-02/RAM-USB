package accesslog

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// openWriter and openReader return two INDEPENDENT file descriptions for
// the same path - not the same *os.File used for both writing and
// reading. This matters: a single fd's read and write calls share one
// underlying kernel file offset, so a write from a handle also used for
// reading advances that shared offset past the very bytes it just wrote,
// making a subsequent Read on the SAME handle see EOF again forever
// (confirmed live via a minimal repro during this test's own
// development). Production usage never hits this: the writer is step-ca
// (a separate process, in a separate container - see
// deployments/compose/certificate-authority.yml's tee-based log capture)
// and the reader is this sidecar's own os.Open call in main.go, always
// two independent file descriptions already.
func openWriter(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func openReader(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// Requirement: CA-F-03
func TestFollow_DeliversLinesAppendedAfterStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	w := openWriter(t, path)

	// Follow only ever sees lines appended AFTER it starts reading, same
	// as main.go's real Seek-to-EOF-then-Follow usage - write one line
	// before Follow starts, to prove it is genuinely ignored.
	if _, err := w.WriteString("{\"status\":100,\"duration-ns\":1}\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}

	r := openReader(t, path)
	if _, err := r.Seek(0, io.SeekEnd); err != nil {
		t.Fatalf("Seek: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan []byte, 4)
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, r, 10*time.Millisecond, func(line []byte) {
			cp := append([]byte(nil), line...)
			got <- cp
		})
	}()

	// Give Follow a moment to reach its first poll, then append two more
	// lines - these, and only these, must be delivered.
	time.Sleep(30 * time.Millisecond)
	if _, err := w.WriteString("{\"status\":200,\"duration-ns\":111}\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if _, err := w.WriteString("{\"status\":500,\"duration-ns\":222}\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}

	want := []string{
		`{"status":200,"duration-ns":111}`,
		`{"status":500,"duration-ns":222}`,
	}
	for i, w := range want {
		select {
		case line := <-got:
			if string(line) != w {
				t.Fatalf("line %d = %q, want %q", i, line, w)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for line %d", i)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Follow returned err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Follow did not return after context cancellation")
	}
}

// Requirement: CA-F-03
func TestFollow_BuffersAPartialLineAcrossPolls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	w := openWriter(t, path)
	r := openReader(t, path)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan []byte, 1)
	go func() {
		_ = Follow(ctx, r, 10*time.Millisecond, func(line []byte) {
			cp := append([]byte(nil), line...)
			got <- cp
		})
	}()

	// Write a line in two pieces, with a pause in between spanning at
	// least one poll interval - Follow must not deliver anything until
	// the newline-terminated second piece arrives.
	if _, err := w.WriteString(`{"status":200,`); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := w.WriteString("\"duration-ns\":42}\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}

	select {
	case line := <-got:
		want := `{"status":200,"duration-ns":42}`
		if string(line) != want {
			t.Fatalf("line = %q, want %q", line, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the reassembled line")
	}
}
