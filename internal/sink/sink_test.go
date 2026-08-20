package sink

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStdoutWritesOneTrailingNewline(t *testing.T) {
	var buf bytes.Buffer
	if err := NewWriter(&buf).Deliver(context.Background(), []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if got := buf.String(); got != "{\"a\":1}\n" {
		t.Errorf("wrote %q", got)
	}
}

func TestFileCreatesParentDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "report.json")
	if err := NewFile(path).Deliver(context.Background(), []byte("payload")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.TrimSpace(string(data)) != "payload" {
		t.Errorf("content = %q", data)
	}
}

// The write must be atomic: a reader watching the path sees either the old
// report or the new one, never a partial file, and no temp file is left over.
func TestFileWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	f := NewFile(path)
	if err := f.Deliver(context.Background(), []byte("first")); err != nil {
		t.Fatalf("first Deliver: %v", err)
	}
	if err := f.Deliver(context.Background(), []byte("second")); err != nil {
		t.Fatalf("second Deliver: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "second" {
		t.Errorf("content = %q, want the second write", data)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".fastrecon-") {
			t.Errorf("temp file %q left behind", e.Name())
		}
	}
}

type failing struct{}

func (failing) Name() string                          { return "failing" }
func (failing) Deliver(context.Context, []byte) error { return errors.New("boom") }

// One dead destination must not cost the others their report.
func TestDeliverAllContinuesPastAFailure(t *testing.T) {
	var buf bytes.Buffer
	results := DeliverAll(context.Background(), []byte("payload"), []Sink{failing{}, NewWriter(&buf)})

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if buf.Len() == 0 {
		t.Error("the healthy sink received nothing after the first one failed")
	}
	err := Errs(results)
	if err == nil {
		t.Fatal("Errs returned nil despite a failed delivery")
	}
	if !strings.Contains(err.Error(), "failing sink") {
		t.Errorf("error %q does not name the sink that failed", err)
	}
}

// A destination that is not a regular file — /dev/stdout, /dev/null, a fifo —
// cannot be replaced by a rename, and there is nothing to make atomic.
func TestFileWritesDirectlyToCharacterDevices(t *testing.T) {
	if err := NewFile("/dev/null").Deliver(context.Background(), []byte("payload")); err != nil {
		t.Errorf("writing to /dev/null failed: %v", err)
	}
}
