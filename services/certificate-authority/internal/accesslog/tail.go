package accesslog

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Follow reads f from its current file position forward, calling onLine
// once for every complete newline-terminated line appended to f from that
// point on, until ctx is canceled. It never seeks and never re-delivers a
// line already read - callers wanting to skip whatever f already contains
// at startup (main.go's real usage: this sidecar only reports on requests
// from the moment it starts, not step-ca's entire history) must
// f.Seek(0, io.SeekEnd) before calling Follow.
//
// f is a real, ever-growing regular file (step-ca's own access log,
// written by a separate process/container - see
// deployments/compose/certificate-authority.yml), not a pipe: a Read past
// the current end of file returns io.EOF, but a later Read on the same
// file description after more data has been written returns that new data
// with no error - this is the standard, well-established polling "tail -f"
// idiom for a regular file, not a bug workaround. pollInterval bounds how
// long Follow waits, on an EOF, before retrying.
//
// A poll can land mid-write, between the writer's own partial-line and
// trailing-newline syscalls - Follow buffers that partial data (pending)
// across polls rather than discarding or delivering it prematurely, so a
// line is only ever handed to onLine once it is complete.
func Follow(ctx context.Context, f *os.File, pollInterval time.Duration, onLine func(line []byte)) error {
	reader := bufio.NewReader(f)
	var pending []byte

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		chunk, err := reader.ReadBytes('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf("accesslog: read: %w", err)
			}
			pending = append(pending, chunk...)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pollInterval):
			}
			continue
		}

		if len(pending) > 0 {
			chunk = append(pending, chunk...)
			pending = nil
		}
		onLine(bytes.TrimRight(chunk, "\n"))
	}
}
