// Package tls inspects the TLS certificate and handshake of a host:port.
// It intentionally skips certificate verification during the handshake so it
// can still inspect expired or otherwise invalid certificates, then judges
// validity itself and reports findings.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// Scanner performs a TLS handshake and reports on the served certificate.
type Scanner struct {
	timeout    time.Duration
	expiryWarn time.Duration // emit a warning when the cert expires within this window
}

// Option configures the scanner.
type Option func(*Scanner)

// WithTimeout sets the dial/handshake timeout.
func WithTimeout(d time.Duration) Option { return func(s *Scanner) { s.timeout = d } }

// New builds a tls scanner with sensible defaults.
func New(opts ...Option) *Scanner {
	s := &Scanner{timeout: 10 * time.Second, expiryWarn: 15 * 24 * time.Hour}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Name implements model.Scanner.
func (s *Scanner) Name() string { return "tls" }

// Scan implements model.Scanner.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return fmt.Errorf("tls: empty target")
	}
	port := t.Port
	if port == 0 {
		port = 443
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: s.timeout}
	// InsecureSkipVerify so the handshake does not fail on an expired/invalid
	// cert — we want to inspect it, not trust it. ServerName drives SNI.
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // inspection scanner, verification done manually below
	})
	if err != nil {
		return fmt.Errorf("tls: dial %s: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("tls: no peer certificate from %s", addr)
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()

	// Base info finding: what the server served.
	emit(model.Finding{
		Scanner:  s.Name(),
		Target:   t,
		Severity: model.SeverityInfo,
		Title:    "TLS certificate",
		Evidence: map[string]any{
			"subject":   leaf.Subject.CommonName,
			"issuer":    leaf.Issuer.CommonName,
			"not_after": leaf.NotAfter.UTC().Format(time.RFC3339),
			"dns_names": leaf.DNSNames,
			"version":   tlsVersionName(state.Version),
			"cipher":    tls.CipherSuiteName(state.CipherSuite),
		},
	})

	// Expiry judgement.
	switch {
	case now.After(leaf.NotAfter):
		emit(model.Finding{
			Scanner: s.Name(), Target: t, Severity: model.SeverityHigh,
			Title:    "TLS certificate expired",
			Evidence: map[string]any{"not_after": leaf.NotAfter.UTC().Format(time.RFC3339)},
		})
	case now.Add(s.expiryWarn).After(leaf.NotAfter):
		emit(model.Finding{
			Scanner: s.Name(), Target: t, Severity: model.SeverityMedium,
			Title:    "TLS certificate expiring soon",
			Evidence: map[string]any{"not_after": leaf.NotAfter.UTC().Format(time.RFC3339)},
		})
	}

	// Not-yet-valid certificate.
	if now.Before(leaf.NotBefore) {
		emit(model.Finding{
			Scanner: s.Name(), Target: t, Severity: model.SeverityMedium,
			Title:    "TLS certificate not yet valid",
			Evidence: map[string]any{"not_before": leaf.NotBefore.UTC().Format(time.RFC3339)},
		})
	}

	// Obsolete protocol version.
	if state.Version < tls.VersionTLS12 {
		emit(model.Finding{
			Scanner: s.Name(), Target: t, Severity: model.SeverityMedium,
			Title:    "obsolete TLS protocol version",
			Evidence: map[string]any{"version": tlsVersionName(state.Version)},
		})
	}

	return nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
