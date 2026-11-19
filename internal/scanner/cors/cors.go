// Package cors checks a host's CORS policy for misconfigurations: whether it
// reflects an arbitrary request Origin (optionally with credentials) or allows
// any origin. GET-only, one request per host.
package cors

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// probeOrigin is the attacker-controlled origin sent to test reflection.
const probeOrigin = "https://aegis-probe.example"

// Scanner tests CORS over HTTP(S).
type Scanner struct {
	client *http.Client
	scheme string
}

// Option configures the scanner.
type Option func(*Scanner)

// WithClient injects an HTTP client (tests pass httptest's client).
func WithClient(c *http.Client) Option { return func(s *Scanner) { s.client = c } }

// WithScheme forces "http" or "https" (default "https").
func WithScheme(scheme string) Option { return func(s *Scanner) { s.scheme = scheme } }

// New builds a CORS scanner.
func New(opts ...Option) *Scanner {
	s := &Scanner{scheme: "https"}
	for _, o := range opts {
		o(s)
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: 10 * time.Second}
	}
	return s
}

func (s *Scanner) Name() string { return "cors" }

// Scan sends one GET with a probe Origin and classifies the CORS response.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.scheme+"://"+host, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", probeOrigin)
	req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()

	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
	if acao == "" {
		return nil // no CORS
	}

	sev, title := classify(acao, acac)
	if title == "" {
		return nil
	}
	emit(model.Finding{
		Scanner:  "cors",
		Target:   t,
		Severity: sev,
		Title:    title,
		Evidence: map[string]any{"allow_origin": acao, "allow_credentials": acac},
	})
	return nil
}

func classify(acao string, acac bool) (model.Severity, string) {
	switch {
	case acao == probeOrigin && acac:
		return model.SeverityHigh, "CORS reflects arbitrary origin with credentials"
	case acao == probeOrigin:
		return model.SeverityMedium, "CORS reflects arbitrary origin"
	case acao == "*" && acac:
		return model.SeverityHigh, "CORS allows any origin (*) with credentials"
	case acao == "*":
		return model.SeverityInfo, "CORS allows any origin (*)"
	}
	return "", ""
}
