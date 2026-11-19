// Package infoleak detects information disclosure on a host: leaked stack traces
// in error responses (medium) and version banners in headers (info). GET-only.
package infoleak

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

const maxBody = 64 * 1024

// stackSignatures are low-false-positive markers of a leaked stack trace.
var stackSignatures = []string{
	"traceback (most recent call last)",
	"exception in thread",
	"at java.",
	"java.lang.",
	"org.springframework",
	"nullpointerexception",
	"system.web.",
	".cs:line",
	"fatal error:",
	"stack trace:",
	"goroutine ",
	"activerecord::",
}

// Scanner checks for information disclosure over HTTP(S).
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

// New builds an infoleak scanner.
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

func (s *Scanner) Name() string { return "infoleak" }

// Scan checks headers for version banners and a few probes for leaked stack
// traces.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return nil
	}
	base := s.scheme + "://" + host

	// Root request: version headers + first stack-trace check.
	hdr, body := s.fetch(ctx, base+"/")
	s.emitVersions(t, hdr, emit)
	if sig := matchStack(body); sig != "" {
		emit(stackFinding(t, "/", sig))
		return nil
	}

	// Error-inducing probes.
	for _, p := range []string{"/aegis-err-xyztest", "/?id=%27%22"} {
		_, b := s.fetch(ctx, base+p)
		if sig := matchStack(b); sig != "" {
			emit(stackFinding(t, p, sig))
			return nil
		}
	}
	return nil
}

func (s *Scanner) emitVersions(t model.Target, h http.Header, emit model.EmitFunc) {
	if h == nil {
		return
	}
	if v := h.Get("Server"); v != "" && strings.ContainsAny(v, "0123456789") {
		emit(versionFinding(t, "Server", v))
	}
	for _, name := range []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"} {
		if v := h.Get(name); v != "" {
			emit(versionFinding(t, name, v))
		}
	}
}

func (s *Scanner) fetch(ctx context.Context, url string) (http.Header, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.Header, string(b)
}

func matchStack(body string) string {
	lb := strings.ToLower(body)
	for _, sig := range stackSignatures {
		if strings.Contains(lb, sig) {
			return sig
		}
	}
	return ""
}

func stackFinding(t model.Target, path, sig string) model.Finding {
	return model.Finding{
		Scanner:  "infoleak",
		Target:   t,
		Severity: model.SeverityMedium,
		Title:    "stack trace leaked in response",
		Evidence: map[string]any{"path": path, "signature": sig},
	}
}

func versionFinding(t model.Target, header, value string) model.Finding {
	return model.Finding{
		Scanner:  "infoleak",
		Target:   t,
		Severity: model.SeverityInfo,
		Title:    "version disclosure: " + header,
		Evidence: map[string]any{"header": header, "value": value},
	}
}
