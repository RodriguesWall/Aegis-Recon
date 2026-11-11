// Package fingerprint detects the technology/stack behind a host by matching
// signatures against the HTTP response (headers and body). In F1 it issues its
// own GET to stay independent of the httpprobe scanner; merging the two
// requests is a possible V2 optimization.
package fingerprint

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

const maxBody = 128 * 1024

// matchKind selects where a signature looks.
type matchKind int

const (
	inHeader matchKind = iota // substring match on a header value (case-insensitive)
	inBody                    // regex match on the body
)

type signature struct {
	kind   matchKind
	header string         // header name when kind == inHeader
	needle string         // lowercase substring when kind == inHeader
	re     *regexp.Regexp // compiled regex when kind == inBody
	tech   string
}

// signatures is a small starter set; extend it over time.
var signatures = []signature{
	{kind: inHeader, header: "Server", needle: "nginx", tech: "nginx"},
	{kind: inHeader, header: "Server", needle: "apache", tech: "Apache"},
	{kind: inHeader, header: "Server", needle: "cloudflare", tech: "Cloudflare"},
	{kind: inHeader, header: "X-Powered-By", needle: "php", tech: "PHP"},
	{kind: inHeader, header: "X-Powered-By", needle: "express", tech: "Express"},
	{kind: inHeader, header: "Set-Cookie", needle: "laravel_session", tech: "Laravel"},
	{kind: inBody, re: regexp.MustCompile(`(?i)wp-content|wp-includes`), tech: "WordPress"},
	{kind: inBody, re: regexp.MustCompile(`__NEXT_DATA__|/_next/`), tech: "Next.js"},
}

// Scanner fingerprints a host over HTTP(S).
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

// New builds a fingerprint scanner.
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
func (s *Scanner) Name() string { return "fingerprint" }

// Scan implements model.Scanner.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return fmt.Errorf("fingerprint: empty target")
	}
	url := s.scheme + "://" + host
	if t.Port != 0 && t.Port != 80 && t.Port != 443 {
		url += ":" + strconv.Itoa(t.Port)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("fingerprint: build request: %w", err)
	}
	req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fingerprint: get %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	detected := map[string]bool{}
	for _, sig := range signatures {
		switch sig.kind {
		case inHeader:
			for _, v := range resp.Header.Values(sig.header) {
				if strings.Contains(strings.ToLower(v), sig.needle) {
					detected[sig.tech] = true
				}
			}
		case inBody:
			if sig.re.Match(body) {
				detected[sig.tech] = true
			}
		}
	}

	for tech := range detected {
		emit(model.Finding{
			Scanner:  s.Name(),
			Target:   t,
			Severity: model.SeverityInfo,
			Title:    "detected technology: " + tech,
			Evidence: map[string]any{"url": url, "technology": tech},
		})
	}
	return nil
}
