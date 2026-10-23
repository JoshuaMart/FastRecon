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
// It costs a second handshake: the HTTP client returns parsed certificate
// fields, not the DER, and its fingerprints are of the certificate, which
// change on every renewal. An SPKI hash survives renewal when the key is
// reused, which is what makes it correlate infrastructure.
func (h *HTTPX) spkiHash(ctx context.Context, host string, port int) string {
	// Bound by the stage context as well as the timeout, or a handshake in
	// flight at the deadline runs on into the output margin.
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: h.opts.Timeout},
		Config: &tls.Config{
			ServerName: host,
			// An expired or self-signed certificate is a finding, not a
			// reason to refuse to look at it.
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		h.opts.Logger.Debug("spki handshake failed", "host", host, "port", port, "error", err)
		return ""
	}
	defer func() { _ = conn.Close() }()

	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
