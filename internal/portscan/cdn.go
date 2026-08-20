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

// classify determines, for every address, whether it belongs to a CDN, WAF or
// cloud provider range.
//
// This runs on every scan regardless of --skip-cdn. Only the restriction is
// optional: "80 and 443 are the only open ports" is indistinguishable from a
// genuinely minimal host unless the report says the scan was narrowed on
// purpose.
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

// cdnEntries builds the report entries for one host: one per provider, each
// naming the addresses it matched, because a host can have both a CDN address
// and an origin address.
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
