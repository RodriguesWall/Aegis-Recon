// Package cookies checks the security attributes of cookies a host sets:
// HttpOnly, Secure and SameSite. GET-only, one request per host.
package cookies

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// Scanner inspects Set-Cookie attributes over HTTP(S).
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

// New builds a cookies scanner.
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

func (s *Scanner) Name() string { return "cookies" }

// Scan fetches the host and emits one finding per cookie missing security flags.
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
	req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()

	for _, c := range resp.Cookies() {
		var missing []string
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if !c.Secure {
			missing = append(missing, "Secure")
		}
		if c.SameSite == 0 { // attribute absent
			missing = append(missing, "SameSite")
		}
		if len(missing) == 0 {
			continue
		}
		sev := model.SeverityLow
		if !c.HttpOnly || !c.Secure {
			sev = model.SeverityMedium
		}
		emit(model.Finding{
			Scanner:  "cookies",
			Target:   t,
			Severity: sev,
			Title:    "insecure cookie: " + c.Name + " (missing " + strings.Join(missing, ", ") + ")",
			Evidence: map[string]any{"cookie": c.Name, "missing": strings.Join(missing, ",")},
		})
	}
	return nil
}
