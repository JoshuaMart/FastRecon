package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strconv"
)

// spkiHash returns the lowercase hex SHA-256 of the certificate's
// SubjectPublicKeyInfo.
//
// It costs a second handshake because the HTTP client hands back the parsed
// certificate fields, not the DER, and the fingerprints it does expose are of
// the certificate — those change on every renewal. An SPKI hash survives
// renewal when the key is reused, which is the whole reason it correlates
// infrastructure.
func (h *HTTPX) spkiHash(ctx context.Context, host string, port int) string {
	dialer := &net.Dialer{Timeout: h.opts.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		ServerName: host,
		// An expired or self-signed certificate is a finding, not a reason to
		// refuse to look at it.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		h.opts.Logger.Debug("spki handshake failed", "host", host, "port", port, "error", err)
		return ""
	}
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
