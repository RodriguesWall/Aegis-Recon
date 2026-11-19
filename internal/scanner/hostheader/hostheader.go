// Package hostheader checks whether a host reflects an attacker-controlled Host
// (or X-Forwarded-Host) header into its redirects or response body — the basis
// for password-reset poisoning and cache poisoning. GET-only; the canary host is
// non-routable.
package hostheader

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

const (
	canary  = "aegis-hhi.example"
	maxBody = 64 * 1024
)

// vector is one way to inject the forged host.
type vector struct {
	name  string
	apply func(*http.Request)
}

var vectors = []vector{
	{"Host", func(r *http.Request) { r.Host = canary }},
	{"X-Forwarded-Host", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", canary) }},
}

// Scanner tests host-header injection over HTTP(S).
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

// New builds the scanner; redirects are not followed so Location is observable.
func New(opts ...Option) *Scanner {
	s := &Scanner{scheme: "https"}
	for _, o := range opts {
		o(s)
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: 10 * time.Second}
	}
	s.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return s
}

func (s *Scanner) Name() string { return "hostheader" }

// Scan tries each injection vector and emits a finding when the canary host is
// reflected into the redirect Location (high) or the response body (medium).
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return nil
	}
	for _, v := range vectors {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.scheme+"://"+host, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")
		v.apply(req)
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()

		switch {
		case strings.Contains(loc, canary):
			emit(s.finding(t, model.SeverityHigh, "host header reflected in redirect ("+v.name+")", v.name, "location", loc))
		case strings.Contains(string(body), canary):
			emit(s.finding(t, model.SeverityMedium, "host header reflected in response body ("+v.name+")", v.name, "body", "canary present"))
		}
	}
	return nil
}

func (s *Scanner) finding(t model.Target, sev model.Severity, title, vec, where, detail string) model.Finding {
	return model.Finding{
		Scanner:  "hostheader",
		Target:   t,
		Severity: sev,
		Title:    title,
		Evidence: map[string]any{"vector": vec, "reflected_in": where, "detail": detail},
	}
}
