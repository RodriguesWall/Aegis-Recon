package openapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

const specJSON = `{
  "openapi": "3.0.0",
  "security": [{"bearer": []}],
  "paths": {
    "/public": { "post": { "security": [] } },
    "/secure": { "post": {} },
    "/items": { "get": {} },
    "/open":  { "delete": { "security": [] } }
  }
}`

func run(t *testing.T, h http.HandlerFunc) []model.Finding {
	t.Helper()
	ts := httptest.NewServer(h)
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	s := New(WithClient(ts.Client()), WithScheme("http"))
	var out []model.Finding
	if err := s.Scan(context.Background(), model.Target{Host: host}, func(f model.Finding) { out = append(out, f) }); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return out
}

func TestUnauthWriteOps(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(specJSON))
			return
		}
		http.NotFound(w, r)
	})
	// /public POST and /open DELETE have security:[] (no auth) -> flagged.
	// /secure POST inherits global security -> not flagged. GET ignored.
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(got), got)
	}
	titles := map[string]bool{}
	for _, f := range got {
		titles[f.Title] = true
		if f.Severity != model.SeverityMedium {
			t.Fatalf("want medium, got %+v", f)
		}
	}
	if !titles["unauthenticated write operation: POST /public"] || !titles["unauthenticated write operation: DELETE /open"] {
		t.Fatalf("wrong findings: %+v", titles)
	}
}

func TestNoSpec(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	if len(got) != 0 {
		t.Fatalf("no spec should yield nothing, got %+v", got)
	}
}

func TestNotASpec(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(`{"hello":"world"}`)) // valid JSON, not a spec
			return
		}
		http.NotFound(w, r)
	})
	if len(got) != 0 {
		t.Fatalf("non-spec JSON should yield nothing, got %+v", got)
	}
}
