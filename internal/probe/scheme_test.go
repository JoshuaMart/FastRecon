package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSchemesPutPlainFirstOnPort80Only(t *testing.T) {
	for port, want := range map[int]string{80: "http", 443: "https", 8080: "https", 8443: "https"} {
		if got := schemes(port)[0]; got != want {
			t.Errorf("port %d tried first over %s, want %s", port, got, want)
		}
	}
}

// plainFirstFor makes a test server's port behave like port 80.
func plainFirstFor(t *testing.T, port int) {
	t.Helper()
	plainFirst[port] = true
	t.Cleanup(func() { delete(plainFirst, port) })
}

// sniffedConn replays the byte read to tell TLS from plain.
type sniffedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c sniffedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// sniffing answers TLS and plain HTTP on one port, from the first byte: the
// front seen on a real port 80.
type sniffing struct {
	net.Listener
	cfg *tls.Config
}

func (l sniffing) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(c)
	b, err := r.Peek(1)
	conn := sniffedConn{c, r}
	if err == nil && b[0] == 0x16 { // a TLS handshake record
		return tls.Server(conn, l.cfg), nil
	}
	return conn, nil
}

// A port that answers both is reported as what a browser sees on port 80:
// plain HTTP. HTTPS first would have reported TLS on port 80.
func TestPlainFirstPortAnsweringBothIsReportedPlain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{selfSigned(t, "127.0.0.1")}}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Redirect(w, r, "https://example.invalid/", http.StatusMovedPermanently)
			return
		}
		_, _ = w.Write([]byte("<title>Secure</title>"))
	})}
	go func() { _ = srv.Serve(sniffing{ln, cfg}) }()
	t.Cleanup(func() { _ = srv.Close() })

	addr := ln.Addr().(*net.TCPAddr)
	plainFirstFor(t, addr.Port)
	got := newRealProber(t, false).probeOne(context.Background(), addr.IP.String(), addr.Port)
	if got == nil || got.Scheme != "http" || got.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("service = %+v, want the plain 301", got)
	}
	if got.TLS != nil {
		t.Error("a plain answer must carry no certificate")
	}
}

// Plain first must not fall back into the trap HTTPS first avoids: a TLS-only
// port answers a plain request with a real 400, which is not a service.
func TestPlainFirstPortThatOnlySpeaksTLSIsReportedTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<title>Secure</title>"))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	host, port := hostPort(t, srv.URL)
	plainFirstFor(t, port)
	got := newRealProber(t, false).probeOne(context.Background(), host, port)
	if got == nil || got.Scheme != "https" || got.StatusCode != http.StatusOK {
		t.Fatalf("service = %+v, want https/200 rather than the plain 400", got)
	}
}

func TestTLSRequiredRecognizesTheKnownAnswers(t *testing.T) {
	for _, body := range []string{
		"<center>The plain HTTP request was sent to HTTPS port</center>",
		"Client sent an HTTP request to an HTTPS server.\n",
		"Reason: You're speaking plain HTTP to an SSL-enabled server port. Instead use the HTTPS scheme. This combination of host and port requires TLS.",
	} {
		if !tlsRequired(http.StatusBadRequest, body) {
			t.Errorf("%q not recognized", body)
		}
	}
	if tlsRequired(http.StatusBadRequest, "bad request") || tlsRequired(http.StatusOK, "plain HTTP request was sent to HTTPS port") {
		t.Error("an ordinary answer read as TLS required")
	}
}
