package infoleak

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

func sevByTitle(fs []model.Finding) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range fs {
		m[f.Title] = f.Severity
	}
	return m
}

func TestStackTrace(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Traceback (most recent call last):\n  File ..."))
	})
	if len(got) != 1 || got[0].Severity != model.SeverityMedium || got[0].Title != "stack trace leaked in response" {
		t.Fatalf("want 1 medium stacktrace, got %+v", got)
	}
}

func TestVersionHeaders(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.21.0")
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.WriteHeader(200)
	})
	m := sevByTitle(got)
	if m["version disclosure: Server"] != model.SeverityInfo || m["version disclosure: X-Powered-By"] != model.SeverityInfo {
		t.Fatalf("want 2 info version disclosures, got %+v", got)
	}
}

func TestClean(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx") // no version number
		w.WriteHeader(200)
	})
	if len(got) != 0 {
		t.Fatalf("clean server should yield nothing, got %+v", got)
	}
}
