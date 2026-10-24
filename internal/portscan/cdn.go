package portscan

import (
	"net"
	"sort"
	"strings"

	"github.com/projectdiscovery/cdncheck"
	"golang.org/x/net/publicsuffix"

	"github.com/JoshuaMart/FastRecon/internal/report"
)

// edge is what the CDN check found for one address.
type edge struct {
	Provider string
	Type     string
}

// classify determines if each address is a CDN/WAF/cloud range (always runs; --skip-cdn only restricts ports).
func classify(client *cdncheck.Client, addresses []string) map[string]edge {
	out := make(map[string]edge, len(addresses))
	if client == nil {
		return out
	}
	for _, addr := range addresses {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		matched, provider, kind, err := client.Check(ip)
		if err != nil || !matched {
			continue
		}
		out[addr] = edge{Provider: provider, Type: kind}
	}
	return out
}

// extraDomains are CDN domains cdncheck's dataset lacks, by registrable
// domain, named as cdncheck names the provider.
var extraDomains = map[string]edge{
	"wscncdn.com": {Provider: "网宿 CDN", Type: "cdn"},
}

// classifyNames marks the addresses of live hosts whose CNAME chain ends at a
// known CDN or WAF domain: an address reached through such a name is the
// provider's edge. Many providers are in cdncheck by their domains only, with
// no address range. An address the ranges already matched keeps that match.
func classifyNames(client *cdncheck.Client, hosts []report.Host, edges map[string]edge) {
	for _, h := range hosts {
		if h.Status != report.StatusLive || len(h.CNAME) == 0 {
			continue
		}
		e, ok := nameEdge(client, h.CNAME)
		if !ok {
			continue
		}
		for _, addr := range h.Addresses {
			if net.ParseIP(addr) == nil {
				continue
			}
			if _, known := edges[addr]; !known {
				edges[addr] = e
			}
		}
	}
}

// nameEdge finds the provider of the first name of a chain that is a known
// CDN or WAF domain. A name that does not parse is skipped, not fatal.
func nameEdge(client *cdncheck.Client, names []string) (edge, bool) {
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		if d, err := publicsuffix.EffectiveTLDPlusOne(n); err == nil {
			if e, ok := extraDomains[d]; ok {
				return e, true
			}
		}
		if client == nil {
			continue
		}
		if matched, provider, kind, err := client.CheckSuffix(n); err == nil && matched {
			return edge{Provider: provider, Type: kind}, true
		}
	}
	return edge{}, false
}

// cdnEntries builds report entries per provider (hosts can have both CDN + origin addresses).
func cdnEntries(addresses []string, edges map[string]edge, limited bool) []report.CDN {
	byProvider := map[edge][]string{}
	for _, addr := range addresses {
		e, ok := edges[addr]
		if !ok {
			continue
		}
		byProvider[e] = append(byProvider[e], addr)
	}
	if len(byProvider) == 0 {
		return nil
	}

	out := make([]report.CDN, 0, len(byProvider))
	for e, matched := range byProvider {
		sort.Strings(matched)
		out = append(out, report.CDN{
			Name:        e.Provider,
			Type:        e.Type,
			Addresses:   matched,
			ScanLimited: limited,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
