// Package exposedfiles probes a host for a small, curated set of sensitive paths
// (VCS metadata, dotfiles, backups, debug/info endpoints, API docs) and reports
// the ones that are actually served. It is GET-only and bounded (short wordlist,
// low concurrency), honoring the project's safety rules.
//
// To cut false positives it first checks a random path: if the server answers
// 200 to that, it soft-404s everything and the host is skipped. Each entry is
// then confirmed by a content signature, or (for signature-less entries) by the
// body not looking like HTML.
package exposedfiles

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

const maxBody = 64 * 1024

// entry is one path to probe. sig is a lowercased substring the body must contain
// to count as a real hit; when empty, the body must simply not look like HTML.
type entry struct {
	path  string
	sev   model.Severity
	sig   string
	title string
}

var entries = []entry{
	{".git/config", model.SeverityHigh, "[core]", "exposed .git/config (source disclosure)"},
	{".git/HEAD", model.SeverityHigh, "ref:", "exposed .git/HEAD (source disclosure)"},
	{".svn/entries", model.SeverityMedium, "", "exposed .svn/entries"},
	{".env", model.SeverityHigh, "", "exposed .env file"},
	{".aws/credentials", model.SeverityHigh, "aws_access_key_id", "exposed AWS credentials"},
	{"backup.zip", model.SeverityHigh, "", "exposed backup archive (backup.zip)"},
	{"backup.sql", model.SeverityHigh, "", "exposed database dump (backup.sql)"},
	{"dump.sql", model.SeverityHigh, "", "exposed database dump (dump.sql)"},
	{"wp-config.php.bak", model.SeverityHigh, "db_password", "exposed wp-config backup"},
	{"phpinfo.php", model.SeverityMedium, "phpinfo()", "exposed phpinfo()"},
	{"server-status", model.SeverityMedium, "apache server status", "exposed Apache server-status"},
	{"actuator/env", model.SeverityHigh, "propertysources", "exposed Spring actuator/env"},
	{"actuator/health", model.SeverityInfo, "status", "Spring actuator/health exposed"},
	{"swagger.json", model.SeverityInfo, "swagger", "API docs exposed (swagger.json)"},
	{"openapi.json", model.SeverityInfo, "openapi", "API docs exposed (openapi.json)"},
	{"api-docs", model.SeverityInfo, "openapi", "API docs exposed (api-docs)"},
}

// Scanner probes for exposed sensitive files over HTTP(S).
type Scanner struct {
	client *http.Client
	scheme string
	conc   int
}

// Option configures the scanner.
type Option func(*Scanner)

// WithClient injects an HTTP client (tests pass httptest's client).
func WithClient(c *http.Client) Option { return func(s *Scanner) { s.client = c } }

// WithScheme forces "http" or "https" (default "https").
func WithScheme(scheme string) Option { return func(s *Scanner) { s.scheme = scheme } }

// New builds the scanner.
func New(opts ...Option) *Scanner {
	s := &Scanner{scheme: "https", conc: 4}
	for _, o := range opts {
		o(s)
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: 8 * time.Second}
	}
	return s
}

func (s *Scanner) Name() string { return "exposedfiles" }

// Scan probes the host and emits a finding per confirmed exposed path.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return nil
	}
	base := s.scheme + "://" + host + "/"

	// Soft-404 baseline: a server that answers 200 to a random path can't be
	// trusted on any 200, so skip it entirely.
	if status, _ := s.get(ctx, base+"aegis-probe-"+randToken()); status == http.StatusOK {
		return nil
	}

	sem := make(chan struct{}, s.conc)
	var wg sync.WaitGroup
	for _, e := range entries {
		wg.Add(1)
		sem <- struct{}{}
		go func(e entry) {
			defer wg.Done()
			defer func() { <-sem }()
			status, body := s.get(ctx, base+e.path)
			if status != http.StatusOK {
				return
			}
			if !confirms(e, body) {
				return
			}
			emit(model.Finding{
				Scanner:  "exposedfiles",
				Target:   t,
				Severity: e.sev,
				Title:    e.title,
				Evidence: map[string]any{"path": "/" + e.path, "status": status},
			})
		}(e)
	}
	wg.Wait()
	return nil
}

// confirms decides whether a 200 body is really the target file.
func confirms(e entry, body string) bool {
	lb := strings.ToLower(body)
	if e.sig != "" {
		return strings.Contains(lb, e.sig)
	}
	return !looksHTML(lb)
}

func looksHTML(lowerBody string) bool {
	return strings.Contains(lowerBody, "<html") || strings.Contains(lowerBody, "<!doctype")
}

// get returns the status and a capped body (empty on error).
func (s *Scanner) get(ctx context.Context, url string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, string(b)
}

func randToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
