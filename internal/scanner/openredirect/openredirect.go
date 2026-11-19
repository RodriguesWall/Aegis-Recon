// Package openredirect checks whether common redirect parameters send the client
// to an attacker-controlled external host. GET-only; redirects are not followed.
package openredirect

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

const (
	canary     = "https://aegis-redirect.example/x"
	canaryHost = "aegis-redirect.example"
)

// redirectParams are the query keys commonly used for post-action redirects.
var redirectParams = []string{
	"next", "url", "return", "returnUrl", "return_url", "redirect",
	"redirect_uri", "redirect_url", "dest", "destination", "continue", "r", "u",
}

// Scanner tests open redirects over HTTP(S).
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

// New builds an open-redirect scanner. The client is forced not to follow
// redirects so the Location header is observable.
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

func (s *Scanner) Name() string { return "openredirect" }

// Scan tests each redirect parameter and emits a finding per one that redirects
// to the external canary host.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return nil
	}
	for _, p := range redirectParams {
		u := s.scheme + "://" + host + "/?" + url.Values{p: {canary}}.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		code := resp.StatusCode
		_ = resp.Body.Close()
		if code < 300 || code >= 400 || loc == "" {
			continue
		}
		if parsed, err := url.Parse(loc); err == nil && parsed.Host == canaryHost {
			emit(model.Finding{
				Scanner:  "openredirect",
				Target:   t,
				Severity: model.SeverityMedium,
				Title:    "open redirect via '" + p + "' parameter",
				Evidence: map[string]any{"param": p, "location": loc},
			})
		}
	}
	return nil
}
