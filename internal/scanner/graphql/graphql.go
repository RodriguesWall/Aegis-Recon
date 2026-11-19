// Package graphql detects whether a GraphQL endpoint has introspection enabled
// (schema disclosure). It sends one benign, read-only introspection query.
package graphql

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

const (
	maxBody = 256 * 1024
	query   = `{"query":"{__schema{queryType{name}}}"}`
)

var endpoints = []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}

// Scanner probes GraphQL introspection over HTTP(S).
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

// New builds a graphql scanner.
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

func (s *Scanner) Name() string { return "graphql" }

// Scan posts an introspection query to candidate endpoints and emits a finding
// when the schema is returned.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return nil
	}
	for _, p := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.scheme+"://"+host+p, bytes.NewBufferString(query))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
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
		body := string(b)
		if strings.Contains(body, "__schema") || strings.Contains(body, "queryType") {
			emit(model.Finding{
				Scanner:  "graphql",
				Target:   t,
				Severity: model.SeverityMedium,
				Title:    "GraphQL introspection enabled",
				Evidence: map[string]any{"path": p},
			})
			return nil
		}
	}
	return nil
}
