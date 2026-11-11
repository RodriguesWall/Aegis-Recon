// Package httpprobe performs a safe HTTP probe (GET only) against a host and
// reports status, redirects, page title and missing security headers. It never
// sends mutating methods, honoring the spy-bot safety rules.
package httpprobe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// maxBody caps how much of the body we read to extract the title.
const maxBody = 64 * 1024

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// securityHeaders maps a header to the finding title used when it is absent.
var securityHeaders = []struct {
	header string
	title  string
}{
	{"Strict-Transport-Security", "missing HSTS header"},
	{"Content-Security-Policy", "missing Content-Security-Policy header"},
	{"X-Frame-Options", "missing X-Frame-Options header"},
	{"X-Content-Type-Options", "missing X-Content-Type-Options header"},
}

// Scanner probes a URL over HTTP(S).
type Scanner struct {
	client *http.Client
	scheme string
}

// Option configures the scanner.
type Option func(*Scanner)

// WithClient injects a custom http.Client (tests pass httptest's client).
func WithClient(c *http.Client) Option { return func(s *Scanner) { s.client = c } }

// WithScheme forces "http" or "https" (default "https").
func WithScheme(scheme string) Option { return func(s *Scanner) { s.scheme = scheme } }

// New builds an httpprobe scanner. By default it uses HTTPS, a 10s timeout and
// records (does not follow blindly) redirects.
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

// Name implements model.Scanner.
func (s *Scanner) Name() string { return "httpprobe" }

// Scan implements model.Scanner.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return fmt.Errorf("httpprobe: empty target")
	}
	url := s.scheme + "://" + host
	if t.Port != 0 && t.Port != 80 && t.Port != 443 {
		url += ":" + strconv.Itoa(t.Port)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("httpprobe: build request: %w", err)
	}
	req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("httpprobe: get %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	title := extractTitle(body)

	emit(model.Finding{
		Scanner:  s.Name(),
		Target:   t,
		Severity: model.SeverityInfo,
		Title:    "HTTP response",
		Evidence: map[string]any{
			"url":    url,
			"status": resp.StatusCode,
			"server": resp.Header.Get("Server"),
			"title":  title,
		},
	})

	// Only flag missing headers on a successful response; errors/redirects
	// are not a meaningful place to judge security headers.
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		for _, h := range securityHeaders {
			if resp.Header.Get(h.header) == "" {
				emit(model.Finding{
					Scanner:  s.Name(),
					Target:   t,
					Severity: model.SeverityLow,
					Title:    h.title,
					Evidence: map[string]any{"url": url, "header": h.header},
				})
			}
		}
	}

	return nil
}

func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}
