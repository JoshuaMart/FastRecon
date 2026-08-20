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
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, f.path); err != nil {
		return fmt.Errorf("rename to %s: %w", f.path, err)
	}
	return nil
}
