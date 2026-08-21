package sink

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// File writes the report to a path, creating parent directories as needed.
//
// The write is atomic — a temporary file in the destination directory, then a
// rename — so a consumer watching the path never reads a half-written report.
type File struct {
	path string
}

// NewFile builds the file sink.
func NewFile(path string) *File { return &File{path: path} }

func (f *File) Name() string { return "file" }

// Path returns the destination, for logging.
func (f *File) Path() string { return f.path }

func (f *File) Deliver(_ context.Context, data []byte) error {
	// A character device or a pipe — /dev/stdout, /dev/null, a fifo — cannot
	// be replaced by a rename, and there is nothing to make atomic: the write
	// goes straight through. Treating these as regular files fails with a
	// permission error that says nothing about the cause.
	if info, err := os.Stat(f.path); err == nil && !info.Mode().IsRegular() {
		return f.writeDirect(data)
	}

	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".fastrecon-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// No-op once the rename succeeded; on any earlier failure it is the cleanup.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	// Owner-only: a report names hosts, open ports and certificates, which is
	// reconnaissance on whoever it describes if the path is shared.
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, f.path); err != nil {
		return fmt.Errorf("rename to %s: %w", f.path, err)
	}
	return nil
}

// writeDirect appends to a destination that is not a regular file.
func (f *File) writeDirect(data []byte) error {
	file, err := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", f.path, err)
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write %s: %w", f.path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", f.path, err)
	}
	return nil
}
