package stage

import "testing"

func TestParseScopeRejectsArbitraryCombinations(t *testing.T) {
	for _, in := range []string{"enumerate,httpprobe", "", "ENUM", "everything"} {
		if _, err := ParseScope(in); err == nil {
			t.Errorf("ParseScope(%q) succeeded, want an error", in)
		}
	}
}

func TestScopeLadderIsCumulative(t *testing.T) {
	prev := 0
	for _, s := range Scopes() {
		stages := s.Stages()
		if len(stages) <= prev {
			t.Fatalf("scope %s has %d stages, want more than the scope below (%d)", s, len(stages), prev)
		}
		if stages[0] != Enumerate {
			t.Errorf("scope %s starts at %s, want %s", s, stages[0], Enumerate)
		}
		prev = len(stages)
	}
}

func TestScopeIncludes(t *testing.T) {
	if ScopeEnum.Includes(Resolve) {
		t.Error("enum scope must not include the resolve stage")
	}
	if !ScopeFull.Includes(HTTPProbe) {
		t.Error("full scope must include the httpprobe stage")
	}
	if !ScopePorts.Includes(Resolve) {
		t.Error("ports scope must include resolve: the port scan needs addresses")
	}
	if ScopePorts.Includes(HTTPProbe) {
		t.Error("ports scope must stop before httpprobe")
	}
}
