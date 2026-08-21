package portscan

import (
	"net"
	"sort"

	"github.com/projectdiscovery/cdncheck"

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
