package resolve

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeResolverServer answers A queries from a table, over a real socket, so
// checkResolver is exercised through the same DNS client the run uses.
//
// A name mapped to nil answers NOERROR with no address — a resolver that
// works while the anchor itself has gone. A name absent from the table gets
// NXDOMAIN, which is what the negative anchor expects.
type fakeResolverServer struct {
	addresses map[string][]string
	// hijack answers every otherwise-unknown name with this address, which is
	// what an NXDOMAIN-rewriting resolver does.
	hijack string
}

func (f *fakeResolverServer) start(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(f.handle)}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return conn.LocalAddr().String()
}

func (f *fakeResolverServer) handle(w dns.ResponseWriter, req *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	for _, q := range req.Question {
		if q.Qtype != dns.TypeA {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")

		addrs, known := f.addresses[name]
		if !known {
			if f.hijack == "" {
				msg.Rcode = dns.RcodeNameError
				continue
			}
			addrs = []string{f.hijack}
		}
		for _, a := range addrs {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(a),
			}
			msg.Answer = append(msg.Answer, rr)
		}
	}
	_ = w.WriteMsg(msg)
}

func TestCheckResolverVerdicts(t *testing.T) {
	// Named so the intent survives a change to the anchor list itself.
	first, second := healthAnchors[0], healthAnchors[1]

	cases := map[string]struct {
		server *fakeResolverServer
		want   string
	}{
		"answers the first anchor correctly": {
			&fakeResolverServer{addresses: map[string][]string{
				first.name: {first.addresses[0]},
			}},
			"",
		},
		// The case the anchor list exists for: an anchor stops resolving, and
		// a healthy resolver must not be condemned for saying so.
		"first anchor has gone, second still answers": {
			&fakeResolverServer{addresses: map[string][]string{
				first.name:  nil,
				second.name: {second.addresses[0]},
			}},
			"",
		},
		// One wrong answer can be a split-horizon view; a second opinion is
		// what tells that apart from a resolver answering for someone else.
		"wrong on the first anchor, right on the second": {
			&fakeResolverServer{addresses: map[string][]string{
				first.name:  {"203.0.113.1"},
				second.name: {second.addresses[0]},
			}},
			"",
		},
		"wrong on every anchor": {
			&fakeResolverServer{addresses: map[string][]string{
				first.name:            {"203.0.113.1"},
				second.name:           {"203.0.113.2"},
				healthAnchors[2].name: {"203.0.113.3"},
			}},
			dropLying,
		},
		"no anchor has an address": {
			&fakeResolverServer{addresses: map[string][]string{
				first.name:            nil,
				second.name:           nil,
				healthAnchors[2].name: nil,
			}},
			dropUnreachable,
		},
		"rewrites NXDOMAIN": {
			&fakeResolverServer{
				addresses: map[string][]string{first.name: {first.addresses[0]}},
				hijack:    "203.0.113.99",
			},
			dropHijacker,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			addr := tc.server.start(t)
			if got := checkResolver(addr, 2*time.Second); got != tc.want {
				t.Errorf("checkResolver = %q, want %q", got, tc.want)
			}
		})
	}
}

// A resolver that does not answer at all must cost one query, not one per
// anchor: on a list of thousands, the difference is the whole health budget.
func TestUnreachableResolverIsNotAskedEveryAnchor(t *testing.T) {
	// A port nothing listens on: every query times out.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	const timeout = 300 * time.Millisecond
	start := time.Now()
	got := checkResolver(addr, timeout)
	elapsed := time.Since(start)

	if got != dropUnreachable {
		t.Errorf("checkResolver = %q, want %q", got, dropUnreachable)
	}
	// One anchor's worth of attempts, with generous headroom for the client's
	// own retry, but well short of asking all three.
	if ceiling := time.Duration(len(healthAnchors)) * timeout; elapsed >= ceiling {
		t.Errorf("took %s, want well under %s: every anchor was tried on a dead resolver", elapsed, ceiling)
	}
}
