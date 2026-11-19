// Package methods detects dangerous HTTP methods on a host: write verbs
// (PUT/DELETE/PATCH) advertised via OPTIONS, and TRACE (cross-site tracing).
// It never sends a mutating request — write methods are only reported from the
// OPTIONS Allow header; only OPTIONS and the non-mutating TRACE are issued.
package methods

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

var writeMethods = []string{"PUT", "DELETE", "PATCH"}

// Scanner probes HTTP methods over HTTP(S).
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

// New builds a methods scanner.
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

func (s *Scanner) Name() string { return "methods" }

// Scan reports write methods from the OPTIONS Allow header and whether TRACE is
// enabled.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return nil
	}
	url := s.scheme + "://" + host

	// OPTIONS → Allow header (read-only).
	if resp, err := s.do(ctx, http.MethodOptions, url); err == nil {
		allow := resp.Header.Get("Allow")
		_ = resp.Body.Close()
		var found []string
		up := strings.ToUpper(allow)
		for _, m := range writeMethods {
			if strings.Contains(up, m) {
				found = append(found, m)
			}
		}
		if len(found) > 0 {
			emit(model.Finding{
				Scanner:  "methods",
				Target:   t,
				Severity: model.SeverityMedium,
				Title:    "write methods enabled: " + strings.Join(found, ", "),
				Evidence: map[string]any{"allow": allow, "methods": strings.Join(found, ",")},
			})
		}
	}

	// TRACE (non-mutating) → enabled if it answers 200 (cross-site tracing).
	if resp, err := s.do(ctx, http.MethodTrace, url); err == nil {
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status == http.StatusOK {
			emit(model.Finding{
				Scanner:  "methods",
				Target:   t,
				Severity: model.SeverityLow,
				Title:    "TRACE method enabled (cross-site tracing)",
				Evidence: map[string]any{"status": status},
			})
		}
	}
	return nil
}

func (s *Scanner) do(ctx context.Context, method, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")
	return s.client.Do(req)
}
