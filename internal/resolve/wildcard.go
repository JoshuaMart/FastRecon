package resolve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
)

// wildcardSet holds answers a wildcard record returns for one parent domain.
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
	// Every address must belong to wildcard set (mixed with own addresses = real host).
	for _, a := range addresses {
		if _, ok := w.addresses[a]; !ok {
			return false
		}
	}
	return true
}

// maxWildcardParents bounds how many zones are probed for a wildcard record.
//
// Every zone costs WildcardProbes DNS queries, and they are spent before a
// single host is resolved. On a target that names in depth —
// <service>.<env>.<region>.example.com — the distinct zone count runs into the
// thousands, and the probing alone can consume the stage's whole budget for a
// result that says nothing about most of the hosts. Zones are ranked by how
// many hosts they cover, so what the cap drops is what a wildcard record there
// would have explained the least.
const maxWildcardParents = 500

// wildcards maps a parent domain to the answers its wildcard record returns.
type wildcards struct {
	byParent map[string]*wildcardSet
	// unprobed counts the zones the cap left out, so a run says so rather
	// than reporting a narrowed check as an exhaustive one.
	unprobed int
}

// covers reports if a host's answers match a parent's wildcard.
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

// detectWildcards probes random names under every parent domain (per-parent detection catches *.dev.example.com too).
func (r *DNSX) detectWildcards(ctx context.Context, hosts []string) *wildcards {
	parents, unprobed := candidateParents(hosts, r.opts.Domain)
	out := &wildcards{byParent: make(map[string]*wildcardSet), unprobed: unprobed}
	if len(parents) == 0 {
		return out
	}

	var mu sync.Mutex
	workers(ctx, len(parents), r.opts.Concurrency, func(i int) {
		if set := r.probeWildcard(ctx, parents[i]); set != nil {
			mu.Lock()
			out.byParent[parents[i]] = set
			mu.Unlock()
		}
	})

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

// candidateParents lists the domains worth probing for a wildcard record:
// each host's ancestors, down to and including the root, ranked by how many
// hosts they cover and capped at maxWildcardParents. It also returns how many
// zones the cap left out.
//
// The root is always probed and always first: it is the run's own domain, and
// a wildcard there is the case that turns a whole enumeration into noise.
func candidateParents(hosts []string, root string) (parents []string, unprobed int) {
	if root == "" {
		return nil, 0
	}

	covered := map[string]int{}
	for _, h := range hosts {
		for _, p := range parentsOf(h) {
			if p != root && strings.HasSuffix(p, "."+root) {
				covered[p]++
			}
		}
	}

	ranked := make([]string, 0, len(covered))
	for p := range covered {
		ranked = append(ranked, p)
	}
	// Most-covering first, name as the tie-break: two runs over the same
	// enumeration must probe the same zones, or a wildcard would appear and
	// disappear between runs for no reason a reader could see.
	sort.Slice(ranked, func(i, j int) bool {
		if covered[ranked[i]] != covered[ranked[j]] {
			return covered[ranked[i]] > covered[ranked[j]]
		}
		return ranked[i] < ranked[j]
	})

	if len(ranked) > maxWildcardParents-1 {
		unprobed = len(ranked) - (maxWildcardParents - 1)
		ranked = ranked[:maxWildcardParents-1]
	}
	return append([]string{root}, ranked...), unprobed
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
