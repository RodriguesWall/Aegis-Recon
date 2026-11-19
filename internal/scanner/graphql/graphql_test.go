package graphql

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

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

func TestIntrospectionEnabled(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/graphql" {
			_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
			return
		}
		http.NotFound(w, r)
	})
	if len(got) != 1 || got[0].Severity != model.SeverityMedium || got[0].Evidence["path"] != "/graphql" {
		t.Fatalf("want 1 medium at /graphql, got %+v", got)
	}
}

func TestNoGraphQL(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	if len(got) != 0 {
		t.Fatalf("no graphql should yield nothing, got %+v", got)
	}
}

func TestIntrospectionDisabled(t *testing.T) {
	// Endpoint exists but rejects introspection (no schema in response).
	got := run(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			_, _ = w.Write([]byte(`{"errors":[{"message":"introspection is disabled"}]}`))
			return
		}
		http.NotFound(w, r)
	})
	if len(got) != 0 {
		t.Fatalf("disabled introspection should yield nothing, got %+v", got)
	}
}
