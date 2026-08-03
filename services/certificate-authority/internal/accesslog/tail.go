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
//
// On every EOF Follow also checks f's path for log rotation, since a
// rotated-away log would otherwise return io.EOF forever and freeze CA-F-03's
// counters on a plausible-looking flat line rather than an obvious gap
// (docs/Known_Issues.md KI-43). Both logrotate modes are handled: with
// copytruncate the file shrinks below the current read offset, and Follow
// rewinds to the start of the same file; with the rename mode the path is
// recreated as a new inode, and Follow reopens it (closing the handle it
// opened itself; the caller's own f is never closed here). Any partial line
// buffered from before the rotation is dropped rather than glued onto the
// new file's first line. Whatever the writer appended between the last read
// and a copytruncate is lost - that data loss is inherent to copytruncate,
// not to this reader.
func Follow(ctx context.Context, f *os.File, pollInterval time.Duration, onLine func(line []byte)) error {
	path := f.Name()
	cur := f
	defer func() {
		if cur != f {
			_ = cur.Close()
		}
	}()

	reader := bufio.NewReader(cur)
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

			rotated, err := reopenIfRotated(cur, path)
			if err != nil {
				return err
			}
			if rotated != nil {
				if rotated != cur && cur != f {
					_ = cur.Close()
				}
				cur = rotated
				reader = bufio.NewReader(cur)
				pending = nil
			}

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

// reopenIfRotated reports whether the log at path was rotated out from under
// cur, and returns the file to keep reading from: cur itself rewound to the
// start (copytruncate), a freshly opened handle (rename), or nil when nothing
// rotated. A path that momentarily does not exist - the window between a
// rename and the writer recreating the file - is not an error: it returns
// nil, and the next poll checks again.
func reopenIfRotated(cur *os.File, path string) (*os.File, error) {
	onDisk, err := os.Stat(path)
	if err != nil {
		return nil, nil //nolint:nilerr // a transient missing path is a normal mid-rotation state, retried on the next poll
	}

	open, err := cur.Stat()
	if err != nil {
		return nil, fmt.Errorf("accesslog: stat open log: %w", err)
	}

	if !os.SameFile(onDisk, open) {
		// codeql[go/path-injection] path is the caller's own already-open file, not attacker input.
		f, err := os.Open(path) //nolint:gosec // path is cur's own name, an operator-supplied deployment setting
		if err != nil {
			return nil, fmt.Errorf("accesslog: reopen rotated log %s: %w", path, err)
		}
		return f, nil
	}

	offset, err := cur.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("accesslog: read offset: %w", err)
	}
	if onDisk.Size() >= offset {
		return nil, nil
	}
	if _, err := cur.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("accesslog: rewind truncated log: %w", err)
	}
	return cur, nil
}
