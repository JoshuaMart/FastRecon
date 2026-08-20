package runid

import (
	"strings"
	"testing"
	"time"
)

func TestNewIsChronologicallySortable(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	earlier := New(base)
	later := New(base.Add(time.Second))
	if earlier >= later {
		t.Errorf("ids must sort by time: %q >= %q", earlier, later)
	}
}

func TestNewShapeAndAlphabet(t *testing.T) {
	id := New(time.Now())
	if len(id) != 26 {
		t.Fatalf("len(%q) = %d, want 26", id, len(id))
	}
	for _, r := range id {
		if !strings.ContainsRune(crockford, r) {
			t.Errorf("id %q contains %q, outside the Crockford alphabet", id, r)
		}
	}
}

func TestNewIsUnique(t *testing.T) {
	now := time.Now()
	seen := make(map[string]bool, 1000)
	for range 1000 {
		id := New(now)
		if seen[id] {
			t.Fatalf("duplicate id %q generated within the same millisecond", id)
		}
		seen[id] = true
	}
}
