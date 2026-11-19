// Package openapi finds an exposed OpenAPI/Swagger spec and flags risky
// operations — write methods (POST/PUT/DELETE/PATCH) with no auth requirement.
// It does not enumerate routes; it reports the weakness. Minimal JSON parsing,
// no external dependency. GET-only.
package openapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

const (
	maxBody     = 2 << 20 // 2 MiB
	maxFindings = 25
)

var specPaths = []string{
	"/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs",
	"/swagger/v1/swagger.json", "/api-docs",
}

var writeMethods = []string{"post", "put", "delete", "patch"}

type spec struct {
	OpenAPI  string                                `json:"openapi"`
	Swagger  string                                `json:"swagger"`
	Security []any                                 `json:"security"`
	Paths    map[string]map[string]json.RawMessage `json:"paths"`
}

type operation struct {
	Security *[]any `json:"security"` // nil = inherit global; [] = auth removed
}

// Scanner parses an exposed API spec over HTTP(S).
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

// New builds an openapi scanner.
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

func (s *Scanner) Name() string { return "openapi" }

// Scan fetches the first reachable spec and emits a finding per unauthenticated
// write operation.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return nil
	}

	sp, specPath := s.findSpec(ctx, s.scheme+"://"+host)
	if sp == nil {
		return nil
	}
	globalSecured := len(sp.Security) > 0

	count := 0
	for path, item := range sp.Paths {
		for _, m := range writeMethods {
			raw, ok := item[m]
			if !ok {
				continue
			}
			var op operation
			_ = json.Unmarshal(raw, &op)
			secured := globalSecured
			if op.Security != nil {
				secured = len(*op.Security) > 0
			}
			if secured {
				continue
			}
			emit(model.Finding{
				Scanner:  "openapi",
				Target:   t,
				Severity: model.SeverityMedium,
				Title:    "unauthenticated write operation: " + strings.ToUpper(m) + " " + path,
				Evidence: map[string]any{"spec": specPath, "method": strings.ToUpper(m), "path": path},
			})
			if count++; count >= maxFindings {
				return nil
			}
		}
	}
	return nil
}

// findSpec returns the first path that serves a parseable OpenAPI/Swagger doc.
func (s *Scanner) findSpec(ctx context.Context, base string) (*spec, string) {
	for _, p := range specPaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+p, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		var sp spec
		if json.Unmarshal(b, &sp) == nil && (sp.OpenAPI != "" || sp.Swagger != "") {
			return &sp, p
		}
	}
	return nil, ""
}
