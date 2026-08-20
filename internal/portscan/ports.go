package portscan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Named port selections.
const (
	PortsTop100  = "top-100"
	PortsTop1000 = "top-1000"
	PortsWeb     = "web"
	PortsFull    = "full"
)

// cdnPorts is what a CDN or WAF address is scanned for when the full scan is
// skipped. It matches the engine's own -exclude-cdn behaviour.
var cdnPorts = []int{80, 443}

// webPorts is the curated HTTP-oriented selection: the ports a web service is
// actually found on, rather than the most common ports overall.
var webPorts = []int{
	80, 81, 88, 443, 591, 2082, 2087, 2095, 2096, 3000, 4243, 4993,
	5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008,
	8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172,
	8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983,
	9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981,
	12443, 16080, 18091, 18092, 20720, 28017,
}

// portSpec is a port selection in the form the engine expects: either a
// top-ports tier or an explicit list.
type portSpec struct {
	// TopPorts is the engine's tier name ("100", "1000", "full").
	TopPorts string
	// List is an explicit port expression, e.g. "80,443,8000-8100".
	List string
}

func (p portSpec) String() string {
	if p.TopPorts != "" {
		return "top-" + p.TopPorts
	}
	return p.List
}

// parsePorts turns the configured selection into an engine port spec.
func parsePorts(ports string) (portSpec, error) {
	switch strings.ToLower(strings.TrimSpace(ports)) {
	case PortsTop100:
		return portSpec{TopPorts: "100"}, nil
	case PortsTop1000:
		return portSpec{TopPorts: "1000"}, nil
	case PortsFull:
		return portSpec{TopPorts: "full"}, nil
	case PortsWeb:
		return portSpec{List: joinPorts(webPorts)}, nil
	case "":
		return portSpec{}, fmt.Errorf("ports must not be empty")
	}

	if err := validatePortExpression(ports); err != nil {
		return portSpec{}, err
	}
	return portSpec{List: ports}, nil
}

// validatePortExpression checks an explicit list so a typo is caught here,
// with a message naming the offending part, rather than deep inside the
// engine.
func validatePortExpression(expr string) error {
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return fmt.Errorf("ports %q contains an empty entry", expr)
		}
		lo, hi, isRange := strings.Cut(part, "-")
		if err := validatePort(lo, expr); err != nil {
			return err
		}
		if !isRange {
			continue
		}
		if err := validatePort(hi, expr); err != nil {
			return err
		}
		l, _ := strconv.Atoi(strings.TrimSpace(lo))
		h, _ := strconv.Atoi(strings.TrimSpace(hi))
		if l > h {
			return fmt.Errorf("ports %q has a reversed range %q", expr, part)
		}
	}
	return nil
}

func validatePort(s, expr string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("ports %q contains %q, which is not a port number", expr, s)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("ports %q contains %d, outside 1-65535", expr, n)
	}
	return nil
}

// expand turns a port spec into the concrete list to probe, minus whatever
// --exclude-ports removes.
func (s *Scanner) expand(spec portSpec) ([]int, error) {
	var expr string
	switch spec.TopPorts {
	case "100":
		expr = nmapTop100
	case "1000":
		expr = nmapTop1000
	case "full":
		expr = "1-65535"
	case "":
		expr = spec.List
	default:
		return nil, fmt.Errorf("unknown top-ports tier %q", spec.TopPorts)
	}

	ports, err := expandExpression(expr)
	if err != nil {
		return nil, err
	}
	if s.opts.ExcludePorts == "" {
		return ports, nil
	}

	excluded, err := expandExpression(s.opts.ExcludePorts)
	if err != nil {
		return nil, fmt.Errorf("exclude-%w", err)
	}
	drop := make(map[int]struct{}, len(excluded))
	for _, p := range excluded {
		drop[p] = struct{}{}
	}
	kept := ports[:0]
	for _, p := range ports {
		if _, skip := drop[p]; !skip {
			kept = append(kept, p)
		}
	}
	return kept, nil
}

// expandExpression turns "80,443,8000-8100" into a sorted, deduplicated list.
func expandExpression(expr string) ([]int, error) {
	if err := validatePortExpression(expr); err != nil {
		return nil, err
	}

	seen := map[int]struct{}{}
	var out []int
	add := func(p int) {
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	for _, part := range strings.Split(expr, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		l, _ := strconv.Atoi(strings.TrimSpace(lo))
		if !isRange {
			add(l)
			continue
		}
		h, _ := strconv.Atoi(strings.TrimSpace(hi))
		for p := l; p <= h; p++ {
			add(p)
		}
	}
	sort.Ints(out)
	return out, nil
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}
