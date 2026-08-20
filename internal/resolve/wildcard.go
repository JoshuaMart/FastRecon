package resolve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
)

// wildcardSet is the set of answers a wildcard record hands out for one parent
// domain.
type wildcardSet struct {
	addresses map[string]struct{}
	cnames    map[string]struct{}
}

func (w *wildcardSet) covers(addresses, cnames []string) bool {
	// A host with no answers is not a wildcard artifact; it is simply dead.
	if len(addresses) == 0 && len(cnames) == 0 {
		return false
	}
	for _, c := range cnames {
		if _, ok := w.cnames[normalizeName(c)]; ok {
			return true
		}
	}
	if len(addresses) == 0 {
		return false
	}
	// Every address must belong to the wildcard set. A host that resolves to
	// the wildcard address *and* one of its own is a real host.
	for _, a := range addresses {
		if _, ok := w.addresses[a]; !ok {
			return false
		}
	}
	return true
}

// wildcards maps a parent domain to the answers its wildcard record returns.
type wildcards struct {
	byParent map[string]*wildcardSet
}

// covers reports whether a host's answers are indistinguishable from the
// wildcard of one of its parents.
func (w *wildcards) covers(host string, addresses, cnames []string) (string, bool) {
	if len(w.byParent) == 0 {
		return "", false
	}
	for _, parent := range parentsOf(host) {
		set, ok := w.byParent[parent]
		if !ok {
			continue
		}
		if set.covers(addresses, cnames) {
			return parent, true
		}
	}
	return "", false
}

// detectWildcards probes random names under every parent domain that appears
// in the host list.
//
// Detection is per parent, not only at the root: a wildcard on
// *.dev.example.com is just as capable of flooding the live set as one on the
// apex, and only the parent it sits on can reveal it.
func (r *DNSX) detectWildcards(ctx context.Context, hosts []string) *wildcards {
	parents := candidateParents(hosts, r.opts.Domain)
	out := &wildcards{byParent: make(map[string]*wildcardSet)}
	if len(parents) == 0 {
		return out
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	sem := make(chan struct{}, r.opts.Concurrency)

	for _, parent := range parents {
		wg.Add(1)
		go func(parent string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if set := r.probeWildcard(ctx, parent); set != nil {
				mu.Lock()
				out.byParent[parent] = set
				mu.Unlock()
			}
		}(parent)
	}
	wg.Wait()

	if len(out.byParent) > 0 {
		names := make([]string, 0, len(out.byParent))
		for p := range out.byParent {
			names = append(names, p)
		}
		r.opts.Logger.Info("wildcard dns detected", "parents", names)
	}
	r.opts.Logger.Debug("wildcard probing finished", "parents_probed", len(parents), "wildcards_found", len(out.byParent))
	return out
}

// probeWildcard resolves random names under parent. It returns the answers
// only when a majority of the probes agree, so one flaky lookup cannot mark a
// whole branch as a wildcard.
func (r *DNSX) probeWildcard(ctx context.Context, parent string) *wildcardSet {
	set := &wildcardSet{addresses: map[string]struct{}{}, cnames: map[string]struct{}{}}
	answered := 0

	for range r.opts.WildcardProbes {
		if ctx.Err() != nil {
			return nil
		}
		data, err := r.query(randomLabel() + "." + parent)
		if err != nil || data == nil {
			continue
		}
		addresses, cnames := answersOf(data)
		if len(addresses) == 0 && len(cnames) == 0 {
			continue
		}
		answered++
		for _, a := range addresses {
			set.addresses[a] = struct{}{}
		}
		for _, c := range cnames {
			set.cnames[normalizeName(c)] = struct{}{}
		}
	}

	if answered*2 <= r.opts.WildcardProbes {
		return nil
	}
	return set
}

// candidateParents lists every domain that could carry a wildcard record for
// the given hosts: each host's ancestors, down to and including the root.
func candidateParents(hosts []string, root string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(d string) {
		if d == "" {
			return
		}
		if _, ok := seen[d]; ok {
			return
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}

	add(root)
	for _, h := range hosts {
		for _, p := range parentsOf(h) {
			if p == root || strings.HasSuffix(p, "."+root) {
				add(p)
			}
		}
	}
	return out
}

// parentsOf returns a host's ancestors, closest first: for a.b.example.com,
// b.example.com then example.com. It stops before a bare TLD, which cannot
// carry a wildcard record anyone here cares about.
func parentsOf(host string) []string {
	var out []string
	rest := host
	for {
		_, after, found := strings.Cut(rest, ".")
		if !found || !strings.Contains(after, ".") {
			return out
		}
		out = append(out, after)
		rest = after
	}
}

func randomLabel() string {
	var b [8]byte
	// crypto/rand.Read never fails; it panics on a broken source.
	_, _ = rand.Read(b[:])
	return "fr" + hex.EncodeToString(b[:])
}

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
